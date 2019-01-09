package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/linkai-io/frontend/pkg/initializers"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/policy"
	"github.com/linkai-io/frontend/pkg/token"
	"github.com/linkai-io/frontend/pkg/token/awstoken"
	"github.com/rs/zerolog/log"
)

var (
	env     string
	region  string
	roleMap map[string]string //roleName:roleArn

	systemOrgID     int
	systemUserID    int
	orgClient       am.OrganizationService
	userClient      am.UserService
	policyContainer *policy.Container
	tokener         token.Tokener
)

func init() {
	var err error

	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	roleMap, err = orgRoles()
	if err != nil {
		log.Fatal().Err(err).Msg("error initializing roles")
	}

	policyContainer = policy.New(env, region)
	if err := policyContainer.Init(roleMap); err != nil {
		log.Fatal().Err(err).Msg("error initializing policies")
	}

	log.Info().Str("env", env).Str("region", region).Int("num_roles", len(roleMap)).Msg("lambda authorizer initializing")

	sec := secrets.NewSecretsCache(env, region)

	if systemOrgID, err = sec.SystemOrgID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system org id")
	}

	if systemUserID, err = sec.SystemUserID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system user id")
	}

	orgClient = initializers.OrgClient()
	userClient = initializers.UserClient()
	tokener = awstoken.New(env, region)
}

func orgRoles() (map[string]string, error) {
	roleMap := make(map[string]string, 8)
	for _, roleName := range []string{"internal_owner", "internal_admin", "internal_reviewer", "owner", "admin", "auditor", "editor", "reviewer"} {
		roleMap[roleName] = os.Getenv(roleName)
		if roleMap[roleName] == "" {
			log.Error().Str("roleName", roleName).Msg("had empty value")
			return nil, errors.New("invalid value passed into org role environment var")
		}
	}
	return roleMap, nil
}

func createSystemContext() am.UserContext {
	return &am.UserContextData{
		OrgID:  systemOrgID,
		UserID: systemUserID,
	}
}

// Help function to generate an IAM policy
func generatePolicy(org *am.Organization, user *am.User, accessToken *token.AccessToken, resource string) (events.APIGatewayCustomAuthorizerResponse, error) {
	var roleName string
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: strconv.Itoa(user.UserID)}
	if org.SubscriptionID == am.SubscriptionSystem {
		roleName = "internal_" + accessToken.Groups[0]
	} else {
		roleName = accessToken.Groups[0]
	}

	policy, err := policyContainer.GetPolicy(roleName)
	if err != nil {
		log.Error().Err(err).Str("OrgName", org.OrgName).Str("UserEmail", user.UserEmail).Str("RoleName", roleName).Msg("failed to lookup policy for role by name")
		return returnUnauthorized("policy failure")
	}

	if resource != "" {
		authResponse.PolicyDocument = *policy
	}

	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = map[string]interface{}{
		"FirstName": user.FirstName,
		"LastName":  user.LastName,
		"CognitoID": accessToken.CognitoUserName,
		"Email":     user.UserEmail,
		"UserCID":   user.UserCID,
		"UserID":    user.UserID,
		"OrgID":     org.OrgID,
		"OrgCID":    org.OrgCID,
		"Group":     accessToken.Groups[0], // for now, only one group
	}
	return authResponse, nil
}

func returnUnauthorized(msg string) (events.APIGatewayCustomAuthorizerResponse, error) {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: "error",
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{events.IAMPolicyStatement{
				Effect:   "Deny",
				Action:   []string{"*"},
				Resource: []string{"*"},
			},
			},
		},
		Context: map[string]interface{}{"message": msg, "customErrorMessage": msg},
	}, nil
}

func splitToken(token string) string {
	if strings.HasPrefix(token, "Bearer ") {
		parts := strings.Split(token, "Bearer ")
		return parts[1]
	}
	if strings.HasPrefix(token, "bearer ") {
		parts := strings.Split(token, "bearer ")
		return parts[1]
	}
	return ""
}

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	token := splitToken(event.AuthorizationToken)

	if token == "" {
		log.Error().Msg("Bearer header missing from token")
		return returnUnauthorized("Bearer header missing from token")
	}

	unsafeToken, err := tokener.UnsafeExtractAccess(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("failed to extract token details")
		return returnUnauthorized(err.Error())
	}

	_, org, err := orgClient.GetByAppClientID(ctx, createSystemContext(), unsafeToken.ClientID)
	if err != nil {
		log.Error().Err(err).Msg("failed to lookup organization by client id")
		return returnUnauthorized("internal error")
	}

	accessToken, err := tokener.ValidateAccessToken(ctx, org, token)
	if err != nil {
		if vErr, ok := err.(*jwt.ValidationError); ok {
			if vErr.Errors == jwt.ValidationErrorExpired {
				return returnUnauthorized("token expired")
			}
		}
		log.Error().Err(err).Str("OrgName", org.OrgName).Msg("failed to validate token for organization")
		return returnUnauthorized(err.Error())
	}

	_, user, err := userClient.GetWithOrgID(ctx, createSystemContext(), org.OrgID, accessToken.CognitoUserName)
	if err != nil {
		log.Error().Err(err).Str("OrgName", org.OrgName).Str("CognitoUserName", accessToken.CognitoUserName).Msg("failed to lookup user by org")
		return returnUnauthorized("internal organization error")
	}

	return generatePolicy(org, user, accessToken, event.MethodArn)
}

func main() {
	lambda.Start(handleRequest)
}
