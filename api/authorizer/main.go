package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/clients/user"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/token"
	"github.com/linkai-io/frontend/pkg/token/awstoken"
	"github.com/rs/zerolog/log"
)

var (
	env      string
	region   string
	roleArns []string

	systemOrgID     int
	systemUserID    int
	orgClient       am.OrganizationService
	userClient      am.UserService
	policyContainer *PolicyContainer
	tokener         token.Tokener
)

func init() {
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	roleArns = strings.Split(os.Getenv("APP_ROLES"), ",")
	if len(roleArns) < 1 {
		log.Fatal().Msg("error reading role arns from environment")
	}

	policyContainer = New(env, region)
	if err := policyContainer.Init(roleArns); err != nil {
		log.Fatal().Err(err).Msg("error initializing policies")
	}

	log.Info().Str("env", env).Str("region", region).Int("num_roles", len(roleArns)).Msg("lambda authorizer initializing")

	sec := secrets.NewSecretsCache(env, region)
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	if systemOrgID, err = sec.SystemOrgID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system org id")
	}

	if systemUserID, err = sec.SystemUserID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system user id")
	}

	orgClient = organization.New()
	if err := orgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}

	userClient = user.New()
	if err := userClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing user client")
	}

	tokener = awstoken.New(env, region)
}

func extractRoleName(idToken *token.IDToken) (string, error) {
	roleArn := idToken.Roles[0]
	role := strings.Split(roleArn, "/")
	if len(role) != 2 {
		return "", errors.New("invalid role arn passed in claims")
	}
	return role[1], nil
}

func createSystemContext() am.UserContext {
	return &am.UserContextData{
		OrgID:  systemOrgID,
		UserID: systemUserID,
	}
}

// Help function to generate an IAM policy
func generatePolicy(org *am.Organization, user *am.User, idToken *token.IDToken, resource string) (events.APIGatewayCustomAuthorizerResponse, error) {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: strconv.Itoa(user.UserID)}
	roleName, err := extractRoleName(idToken)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, err
	}

	policy, err := policyContainer.GetRolePolicies(roleName)
	if err != nil {
		log.Error().Err(err).Str("OrgName", org.OrgName).Str("UserEmail", user.UserEmail).Str("RoleName", roleName).Msg("failed to lookup policy for role by name")
		return events.APIGatewayCustomAuthorizerResponse{}, err
	}

	if resource != "" {
		authResponse.PolicyDocument = *policy
	}

	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = map[string]interface{}{
		"FirstName": idToken.FirstName,
		"LastName":  idToken.LastName,
		"CognitoID": idToken.CognitoUserName,
		"UserCID":   user.UserCID,
		"UserID":    user.UserID,
		"OrgID":     org.OrgID,
		"OrgCID":    org.OrgCID,
		"Group":     idToken.Groups[0], // for now, only one group
	}
	log.Info().Msgf("Returning response: %#v\n", authResponse)
	return authResponse, nil
}

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	token := event.AuthorizationToken
	unsafeToken, err := tokener.UnsafeExtractDetails(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("failed to extract token details")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("error invalid token")
	}

	if unsafeToken.OrgName == "" || unsafeToken.Email == "" {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("error invalid token, missing org or email claims")
	}

	_, org, err := orgClient.Get(ctx, createSystemContext(), unsafeToken.OrgName)
	if err != nil {
		log.Error().Err(err).Msg("failed to lookup organization by name")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("error with org service")
	}

	idToken, err := tokener.ValidateToken(ctx, org, token)
	if err != nil {
		log.Error().Err(err).Str("OrgName", org.OrgName).Msg("failed to validate token for organization")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("error: invalid token")
	}

	_, user, err := userClient.GetWithOrgID(ctx, createSystemContext(), org.OrgID, idToken.Email)
	if err != nil {
		log.Error().Err(err).Str("OrgName", org.OrgName).Str("UserEmail", idToken.Email).Msg("failed to lookup user by org")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("error with user service")
	}

	return generatePolicy(org, user, idToken, event.MethodArn)
}

func main() {
	lambda.Start(handleRequest)
}
