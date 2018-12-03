package main

import (
	"context"
	"fmt"
	"os"

	"github.com/linkai-io/am/clients/user"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var userClient am.UserService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Address").Logger()

	sec := secrets.NewSecretsCache(os.Getenv("APP_ENV"), os.Getenv("APP_REGION"))
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	userClient = user.New()
	if err := userClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing user client")
	}
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	resp := events.APIGatewayProxyResponse{Body: request.Body + "DORK", StatusCode: 200}
	route := request.RequestContext.HTTPMethod + request.RequestContext.ResourcePath

	fmt.Printf("route: %v\n", route)
	fmt.Println("Received: ", request.Body)
	fmt.Printf("REQUEST: %#v\n", request.PathParameters)

	switch route {
	case "GET/user/id/":
		return resp, nil
	case "PATCH/user/id/":
		return resp, nil
	case "DELETE/user/id/":
		return resp, nil
	case "GET/user/cid/":
		return resp, nil
	case "GET/users/":
		return resp, nil
	case "PUT/user/":
		return resp, nil
	}
	return resp, nil
}

func main() {
	lambda.Start(Handler)
}
