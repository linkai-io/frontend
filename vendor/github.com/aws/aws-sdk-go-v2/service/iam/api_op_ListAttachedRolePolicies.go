// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package iam

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

// Please also see https://docs.aws.amazon.com/goto/WebAPI/iam-2010-05-08/ListAttachedRolePoliciesRequest
type ListAttachedRolePoliciesInput struct {
	_ struct{} `type:"structure"`

	// Use this parameter only when paginating results and only after you receive
	// a response indicating that the results are truncated. Set it to the value
	// of the Marker element in the response that you received to indicate where
	// the next call should start.
	Marker *string `min:"1" type:"string"`

	// Use this only when paginating results to indicate the maximum number of items
	// you want in the response. If additional items exist beyond the maximum you
	// specify, the IsTruncated response element is true.
	//
	// If you do not include this parameter, the number of items defaults to 100.
	// Note that IAM might return fewer results, even when there are more results
	// available. In that case, the IsTruncated response element returns true, and
	// Marker contains a value to include in the subsequent call that tells the
	// service where to continue from.
	MaxItems *int64 `min:"1" type:"integer"`

	// The path prefix for filtering the results. This parameter is optional. If
	// it is not included, it defaults to a slash (/), listing all policies.
	//
	// This parameter allows (through its regex pattern (http://wikipedia.org/wiki/regex))
	// a string of characters consisting of either a forward slash (/) by itself
	// or a string that must begin and end with forward slashes. In addition, it
	// can contain any ASCII character from the ! (\u0021) through the DEL character
	// (\u007F), including most punctuation characters, digits, and upper and lowercased
	// letters.
	PathPrefix *string `min:"1" type:"string"`

	// The name (friendly name, not ARN) of the role to list attached policies for.
	//
	// This parameter allows (through its regex pattern (http://wikipedia.org/wiki/regex))
	// a string of characters consisting of upper and lowercase alphanumeric characters
	// with no spaces. You can also include any of the following characters: _+=,.@-
	//
	// RoleName is a required field
	RoleName *string `min:"1" type:"string" required:"true"`
}

// String returns the string representation
func (s ListAttachedRolePoliciesInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *ListAttachedRolePoliciesInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "ListAttachedRolePoliciesInput"}
	if s.Marker != nil && len(*s.Marker) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("Marker", 1))
	}
	if s.MaxItems != nil && *s.MaxItems < 1 {
		invalidParams.Add(aws.NewErrParamMinValue("MaxItems", 1))
	}
	if s.PathPrefix != nil && len(*s.PathPrefix) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("PathPrefix", 1))
	}

	if s.RoleName == nil {
		invalidParams.Add(aws.NewErrParamRequired("RoleName"))
	}
	if s.RoleName != nil && len(*s.RoleName) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("RoleName", 1))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// Contains the response to a successful ListAttachedRolePolicies request.
// Please also see https://docs.aws.amazon.com/goto/WebAPI/iam-2010-05-08/ListAttachedRolePoliciesResponse
type ListAttachedRolePoliciesOutput struct {
	_ struct{} `type:"structure"`

	// A list of the attached policies.
	AttachedPolicies []AttachedPolicy `type:"list"`

	// A flag that indicates whether there are more items to return. If your results
	// were truncated, you can make a subsequent pagination request using the Marker
	// request parameter to retrieve more items. Note that IAM might return fewer
	// than the MaxItems number of results even when there are more results available.
	// We recommend that you check IsTruncated after every call to ensure that you
	// receive all your results.
	IsTruncated *bool `type:"boolean"`

	// When IsTruncated is true, this element is present and contains the value
	// to use for the Marker parameter in a subsequent pagination request.
	Marker *string `type:"string"`
}

// String returns the string representation
func (s ListAttachedRolePoliciesOutput) String() string {
	return awsutil.Prettify(s)
}

const opListAttachedRolePolicies = "ListAttachedRolePolicies"

// ListAttachedRolePoliciesRequest returns a request value for making API operation for
// AWS Identity and Access Management.
//
// Lists all managed policies that are attached to the specified IAM role.
//
// An IAM role can also have inline policies embedded with it. To list the inline
// policies for a role, use the ListRolePolicies API. For information about
// policies, see Managed Policies and Inline Policies (https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html)
// in the IAM User Guide.
//
// You can paginate the results using the MaxItems and Marker parameters. You
// can use the PathPrefix parameter to limit the list of policies to only those
// matching the specified path prefix. If there are no policies attached to
// the specified role (or none that match the specified path prefix), the operation
// returns an empty list.
//
//    // Example sending a request using ListAttachedRolePoliciesRequest.
//    req := client.ListAttachedRolePoliciesRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/iam-2010-05-08/ListAttachedRolePolicies
func (c *Client) ListAttachedRolePoliciesRequest(input *ListAttachedRolePoliciesInput) ListAttachedRolePoliciesRequest {
	op := &aws.Operation{
		Name:       opListAttachedRolePolicies,
		HTTPMethod: "POST",
		HTTPPath:   "/",
		Paginator: &aws.Paginator{
			InputTokens:     []string{"Marker"},
			OutputTokens:    []string{"Marker"},
			LimitToken:      "MaxItems",
			TruncationToken: "IsTruncated",
		},
	}

	if input == nil {
		input = &ListAttachedRolePoliciesInput{}
	}

	req := c.newRequest(op, input, &ListAttachedRolePoliciesOutput{})
	return ListAttachedRolePoliciesRequest{Request: req, Input: input, Copy: c.ListAttachedRolePoliciesRequest}
}

// ListAttachedRolePoliciesRequest is the request type for the
// ListAttachedRolePolicies API operation.
type ListAttachedRolePoliciesRequest struct {
	*aws.Request
	Input *ListAttachedRolePoliciesInput
	Copy  func(*ListAttachedRolePoliciesInput) ListAttachedRolePoliciesRequest
}

// Send marshals and sends the ListAttachedRolePolicies API request.
func (r ListAttachedRolePoliciesRequest) Send(ctx context.Context) (*ListAttachedRolePoliciesResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &ListAttachedRolePoliciesResponse{
		ListAttachedRolePoliciesOutput: r.Request.Data.(*ListAttachedRolePoliciesOutput),
		response:                       &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// NewListAttachedRolePoliciesRequestPaginator returns a paginator for ListAttachedRolePolicies.
// Use Next method to get the next page, and CurrentPage to get the current
// response page from the paginator. Next will return false, if there are
// no more pages, or an error was encountered.
//
// Note: This operation can generate multiple requests to a service.
//
//   // Example iterating over pages.
//   req := client.ListAttachedRolePoliciesRequest(input)
//   p := iam.NewListAttachedRolePoliciesRequestPaginator(req)
//
//   for p.Next(context.TODO()) {
//       page := p.CurrentPage()
//   }
//
//   if err := p.Err(); err != nil {
//       return err
//   }
//
func NewListAttachedRolePoliciesPaginator(req ListAttachedRolePoliciesRequest) ListAttachedRolePoliciesPaginator {
	return ListAttachedRolePoliciesPaginator{
		Pager: aws.Pager{
			NewRequest: func(ctx context.Context) (*aws.Request, error) {
				var inCpy *ListAttachedRolePoliciesInput
				if req.Input != nil {
					tmp := *req.Input
					inCpy = &tmp
				}

				newReq := req.Copy(inCpy)
				newReq.SetContext(ctx)
				return newReq.Request, nil
			},
		},
	}
}

// ListAttachedRolePoliciesPaginator is used to paginate the request. This can be done by
// calling Next and CurrentPage.
type ListAttachedRolePoliciesPaginator struct {
	aws.Pager
}

func (p *ListAttachedRolePoliciesPaginator) CurrentPage() *ListAttachedRolePoliciesOutput {
	return p.Pager.CurrentPage().(*ListAttachedRolePoliciesOutput)
}

// ListAttachedRolePoliciesResponse is the response type for the
// ListAttachedRolePolicies API operation.
type ListAttachedRolePoliciesResponse struct {
	*ListAttachedRolePoliciesOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// ListAttachedRolePolicies request.
func (r *ListAttachedRolePoliciesResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
