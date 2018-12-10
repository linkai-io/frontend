package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var orgClient am.OrganizationService
var orgProvisioner *provision.OrgProvisioner
var env string
var region string

var systemOrgID int
var systemUserID int

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "AuthAPI").Logger()
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	log.Info().Str("env", env).Str("region", region).Msg("authapi initializing")

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

	log.Info().Int("org_id", systemOrgID).Int("user_id", systemUserID).Msg("auth handler configured with system ids")
	orgClient = organization.New()
	if err := orgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}

	log.Info().Str("load_balancer", lb).Msg("orgClient initialized with lb")
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	resp := events.APIGatewayProxyResponse{Body: request.Body + "DORK", StatusCode: 200}
	route := request.RequestContext.HTTPMethod + request.RequestContext.ResourcePath

	fmt.Printf("route: %v\n", route)
	fmt.Println("Received: ", request.Body)
	fmt.Printf("REQUEST: %#v\n", request.PathParameters)

	switch route {
	case "POST/login":
		return resp, nil
	case "POST/reset":
		return resp, nil
	case "GET/logout":
		return resp, nil
	case "POST/changepwd":
		return resp, nil
	case "GET/org/list/":
		return resp, nil
	case "PATCH/org/id/":
		return resp, nil
	case "DELETE/org/id/":
		return resp, nil
	}
	return resp, nil

	return events.APIGatewayProxyResponse{Body: request.Body + "DORK", StatusCode: 200}, nil
}

func main() {
	lambda.Start(Handler)
}
