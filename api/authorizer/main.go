package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/clients/user"
	"github.com/linkai-io/am/pkg/secrets"
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

}

// Help function to generate an IAM policy
func generatePolicy(principalId, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalId}
	log.Info().Str("principal", principalId).Str("effect", effect).Str("resource", resource).Msg("generating policy")

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = map[string]interface{}{
		"stringKey":  "stringval",
		"numberKey":  123,
		"booleanKey": true,
	}
	return authResponse
}

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	token := event.AuthorizationToken
	switch strings.ToLower(token) {
	case "allow":
		return generatePolicy("user", "Allow", event.MethodArn), nil
	case "deny":
		return generatePolicy("user", "Deny", event.MethodArn), nil
	case "unauthorized":
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized") // Return a 401 Unauthorized response
	default:
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Error: Invalid token")
	}
}

func main() {
	lambda.Start(handleRequest)
}
