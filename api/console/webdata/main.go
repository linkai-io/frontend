package main

import (
	"context"
	"fmt"
	"os"

	"github.com/linkai-io/am/clients/webdata"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var webClient am.WebDataService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Address").Logger()

	sec := secrets.NewSecretsCache(os.Getenv("APP_ENV"), os.Getenv("APP_REGION"))
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	webClient = webdata.New()
	if err := webClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing webdata client")
	}
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	resp := events.APIGatewayProxyResponse{Body: request.Body + "DORK", StatusCode: 200}
	route := request.RequestContext.HTTPMethod + request.RequestContext.ResourcePath

	fmt.Printf("route: %v\n", route)
	fmt.Println("Received: ", request.Body)
	fmt.Printf("REQUEST: %#v\n", request.PathParameters)
	switch route {
	case "GET/web/responses/":
		return resp, nil
	case "GET/web/certificates/":
		return resp, nil
	case "GET/web/snapshots/":
		return resp, nil
	}

	return resp, nil

}

func main() {
	lambda.Start(Handler)
}
