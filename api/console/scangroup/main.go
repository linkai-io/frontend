package main

import (
	"context"
	"fmt"
	"os"

	"github.com/linkai-io/am/clients/scangroup"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var sgClient am.ScanGroupService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "ScanGroup").Logger()

	sec := secrets.NewSecretsCache(os.Getenv("APP_ENV"), os.Getenv("APP_REGION"))
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	sgClient = scangroup.New()
	if err := sgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing scangroup client")
	}
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	resp := events.APIGatewayProxyResponse{Body: request.Body + "DORK", StatusCode: 200}
	route := request.RequestContext.HTTPMethod + request.RequestContext.ResourcePath

	fmt.Printf("route: %v\n", route)
	fmt.Println("Received: ", request.Body)
	fmt.Printf("REQUEST: %#v\n", request.PathParameters)

	switch route {
	case "GET/scangroup/id/":
		return resp, nil
	case "GET/scangroups/":
		return resp, nil
	case "PUT/scangroup/":
		return resp, nil
	case "PATCH/scangroup/id/":
		return resp, nil
	case "PATCH/scangroup/pause/":
		return resp, nil
	case "PATCH/scangroup/resume/":
		return resp, nil
	case "DELETE/scangroup/id/":
		return resp, nil
	}
	fmt.Println("Received: ", request.Body)
	fmt.Printf("REQUEST: %#v\n", request.PathParameters)
	return resp, nil
}

func main() {
	lambda.Start(Handler)
}
