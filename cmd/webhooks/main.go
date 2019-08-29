package main

import (
	"context"
	"os"
	"time"

	"github.com/linkai-io/am/pkg/webhooks"

	"github.com/aws/aws-lambda-go/lambda"
)

var env string
var region string
var client *webhooks.Client

func init() {
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	client = webhooks.NewClient()
}

// HandleRequest by calling out to our webhook client
func HandleRequest(ctx context.Context, evt *webhooks.Data) (*webhooks.DataResponse, error) {
	respCode, err := client.SendEvent(ctx, evt)
	if err != nil {
		return &webhooks.DataResponse{StatusCode: 0, DeliveredTime: 0, Error: err.Error()}, err
	}
	return &webhooks.DataResponse{StatusCode: respCode, DeliveredTime: time.Now().UnixNano()}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
