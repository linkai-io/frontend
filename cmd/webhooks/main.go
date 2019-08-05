package main

import (
	"context"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/webhook"

	"github.com/aws/aws-lambda-go/lambda"
)

var client = webhook.New()

type WebhookEvent struct {
	URL       string      `json:"url"`
	Version   string      `json:"version"`
	Type      string      `json:"type"`
	ScanGroup string      `json:"scan_group"`
	Events    []*am.Event `json:"events"`
}

type WebhookEventResponse struct {
	StatusCode    int    `json:"status_code"`
	DeliveredTime int64  `json:"delivery_time"`
	Error         string `json:"error"`
}

func HandleRequest(ctx context.Context, evt WebhookEvent) (WebhookEventResponse, error) {
	respCode, err := client.SendEvent(evt)
	if err != nil {
		return WebhookEventResponse{StatusCode: 0, DeliveredTime: 0, Error: err.Error()}, err
	}
	return WebhookEventResponse{StatusCode: respCode, DeliveredTime: time.Now().Unix()}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
