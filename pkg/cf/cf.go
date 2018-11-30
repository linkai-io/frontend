package cf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
)

// CustomResourceHandler is the interface for defining the handler called when
// AWS CloudFormation stack including lambda-backed custom resource is created, updated, or deleted.
//
// Create creates the custom resource.
// Create returns physicalResourceID, data and err.
// physicalResourceID is set to PhysicalResourceId field of the custom resource response.
// when physicalResourceID is empty, he automatically generated id is set.
// The value returned as data is a value that can be obtained by Fn::GetAtt from the custom resource of template.
// data must be the type that can be converted to map[string]interface{}.
// When data has multi-level map hierarchy, it is converted into map[string]interface{} with the key name is concatenated by '.'.
// When err is not nil, the creation of custom resource is failed.
//
// Update updates the custom resource.
// Update returns data and err.
// The value returned as data is a value that can be obtained by Fn::GetAtt from the custom resource of template.
// data must be the type that can be converted to map[string]interface{}.
// When data has multi-level map hierarchy, it is converted into map[string]interface{} with the key name is concatenated by '.'.
// When err is not nil, the updating of custom resource is failed.
//
// Delete deletes the custom resource
// Delete returns err.
// When err is not nil, the deleting of custom resource is failed.
type CustomResourceHandler interface {
	Create(ctx context.Context, req Request) (physicalResourceID string, data interface{}, err error)
	Update(ctx context.Context, req Request) (data interface{}, err error)
	Delete(ctx context.Context, req Request) error
}

// StartLambda takes a CustomResourceHandler and starts the lambda function.
func StartLambda(h CustomResourceHandler) {
	lambda.Start(NewLambdaHandler(h))
}

// NewLambdaHandler returns handler function to pass to the lambda.Start of aws-lambda-go.
func NewLambdaHandler(h CustomResourceHandler) func(ctx context.Context, req Request) error {
	return func(ctx context.Context, req Request) error {
		printLog("request", req)

		var data interface{}
		var err error

		switch req.RequestType {
		case RequestTypeCreate:
			req.PhysicalResourceID, data, err = h.Create(ctx, req)
			if req.PhysicalResourceID == "" {
				req.PhysicalResourceID = req.genPhysicalResourceID()
			}
		case RequestTypeUpdate:
			data, err = h.Update(ctx, req)
		case RequestTypeDelete:
			err = h.Delete(ctx, req)
		default:
			err = fmt.Errorf("invalid request")
		}

		if err != nil {
			return req.failed(err)
		}

		return req.success(data)
	}
}

// RequestType represents the custom resource request type.
// see https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-requesttypes.html.
type RequestType string

const (
	// RequestTypeCreate represents request type of Create.
	RequestTypeCreate RequestType = "Create"
	// RequestTypeUpdate represents request type of Update.
	RequestTypeUpdate RequestType = "Update"
	// RequestTypeDelete represents request type of Delete.
	RequestTypeDelete RequestType = "Delete"
)

// Properties represents the key-value properties field type of the Request.
type Properties map[string]interface{}

// Unmarshal converts itsself into type of v and stores the value pointed to by v.
func (p Properties) Unmarshal(v interface{}) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Request represents the AWS CloudFormation lambda-backed custom resource operation request.
// see https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-requests.html.
type Request struct {
	RequestType           RequestType `json:"RequestType,omitempty"`
	ResponseURL           string      `json:"ResponseURL,omitempty"`
	StackID               string      `json:"StackId,omitempty"`
	RequestID             string      `json:"RequestId,omitempty"`
	ResourceType          string      `json:"ResourceType,omitempty"`
	LogicalResourceID     string      `json:"LogicalResourceId,omitempty"`
	PhysicalResourceID    string      `json:"PhysicalResourceId,omitempty"`
	ResourceProperties    Properties  `json:"ResourceProperties,omitempty"`
	OldResourceProperties Properties  `json:"OldResourceProperties,omitempty"`
}

func (r Request) success(data interface{}) error {
	data, err := flattenData(data)
	if err != nil {
		return r.failed(err)
	}

	return r.respond(Response{
		Status:             ResponseStatusSuccess,
		Reason:             "",
		StackID:            r.StackID,
		RequestID:          r.RequestID,
		LogicalResourceID:  r.LogicalResourceID,
		PhysicalResourceID: r.PhysicalResourceID,
		NoEcho:             false,
		Data:               data,
	})
}

func (r Request) failed(err error) error {
	return r.respond(Response{
		Status:             ResponseStatusFailed,
		Reason:             err.Error(),
		StackID:            r.StackID,
		RequestID:          r.RequestID,
		LogicalResourceID:  r.LogicalResourceID,
		PhysicalResourceID: r.PhysicalResourceID,
		NoEcho:             false,
		Data:               nil,
	})
}

func (r Request) respond(res Response) error {
	printLog("response", res)

	b, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("json marshal error: %v", err)
	}

	cli := &http.Client{}
	req, err := http.NewRequest("PUT", r.ResponseURL, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("http request error: %v", err)
	}

	req.ContentLength = int64(len(b))
	cfnres, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("http error: %v", err)
	}
	if cfnres.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("cfnresponse error: %v", cfnres)
	}

	return nil
}

func (r Request) genPhysicalResourceID() string {
	date := time.Now().Format("2006-01-02")
	stack := strings.Split(r.StackID, "/")[1]
	return fmt.Sprintf("%s/%s/%s/%s", date, stack, r.LogicalResourceID, r.RequestID)
}

// ResponseStatus represents the custom resource response status.
type ResponseStatus string

const (
	// ResponseStatusSuccess represents request response of SUCCESS.
	ResponseStatusSuccess ResponseStatus = "SUCCESS"
	// ResponseStatusFailed represents request response of FAILED.
	ResponseStatusFailed ResponseStatus = "FAILED"
)

// Response represents the AWS CloudFormation lambda-backed custom resource operation response.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-responses.html
type Response struct {
	Status             ResponseStatus `json:"Status,omitempty"`
	Reason             string         `json:"Reason,omitempty"`
	StackID            string         `json:"StackId,omitempty"`
	RequestID          string         `json:"RequestId,omitempty"`
	LogicalResourceID  string         `json:"LogicalResourceId,omitempty"`
	PhysicalResourceID string         `json:"PhysicalResourceId,omitempty"`
	NoEcho             bool           `json:"NoEcho,omitempty"`
	Data               interface{}    `json:"Data,omitempty"`
}

func flattenData(data interface{}) (map[string]interface{}, error) {
	if data == nil {
		return nil, nil
	}

	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("invalid data: %v", data)
	}
	x := map[string]interface{}{}
	json.Unmarshal(b, &x)

	result := map[string]interface{}{}
	flatten(result, x, "")
	return result, nil
}

func flatten(result, x map[string]interface{}, parentKey string) {
	for k, v := range x {
		if m, ok := v.(map[string]interface{}); ok {
			flatten(result, m, genKey(parentKey, k))
		} else {
			result[genKey(parentKey, k)] = v
		}
	}
}

func genKey(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

// printLog prints a log for CloudWatch.
func printLog(msg string, x interface{}) {
	var str string
	b, err := json.Marshal(x)
	if err != nil {
		str = fmt.Sprintf("%v", x)
	} else {
		str = string(b)
	}
	log.Printf("%s: %s\n", msg, str)
}
