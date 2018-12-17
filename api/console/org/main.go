package main

import (
	"context"
	"os"

	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var orgClient am.OrganizationService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Org").Logger()

	sec := secrets.NewSecretsCache(os.Getenv("APP_ENV"), os.Getenv("APP_REGION"))
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	orgClient = organization.New()
	if err := orgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	route := request.RequestContext.HTTPMethod + request.Path

	log.Info().Msgf("route: %s, authorizer data: %#v", route)
	for k, v := range request.RequestContext.Authorizer {
		switch typ := v.(type) {
		case string:
			log.Info().Str(k, typ).Msg("authorizer data")
		case int:
			log.Info().Int(k, typ).Msg("authorizer data")
		case int64:
			log.Info().Int64(k, typ).Msg("authorizer data")
		}
	}
	log.Info().Msgf("body: %s", request.Body)

	resp := events.APIGatewayProxyResponse{Body: request.Body + "DORK", StatusCode: 200}
	switch route {
	case "GET/org/name/":
		return resp, nil
	case "GET/org/id/":
		return resp, nil
	case "GET/org/cid/":
		return resp, nil
	case "GET/org/list/":
		return resp, nil
	case "PATCH/org/id/":
		return resp, nil
	case "DELETE/org/id/":
		return resp, nil
	}
	return resp, nil
}

func main() {
	lambda.Start(Handler)
}
