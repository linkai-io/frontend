package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	fmt.Println("Received: ", request.Body)
	fmt.Printf("REQUEST: %#v\n", request.PathParameters)

	return events.APIGatewayProxyResponse{Body: request.Body + "DORK", StatusCode: 200}, nil
}

func main() {
	lambda.Start(Handler)
}
