// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package cognitoidentityprovider

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

// Represents the request to create a user pool.
// Please also see https://docs.aws.amazon.com/goto/WebAPI/cognito-idp-2016-04-18/CreateUserPoolRequest
type CreateUserPoolInput struct {
	_ struct{} `type:"structure"`

	// The configuration for AdminCreateUser requests.
	AdminCreateUserConfig *AdminCreateUserConfigType `type:"structure"`

	// Attributes supported as an alias for this user pool. Possible values: phone_number,
	// email, or preferred_username.
	AliasAttributes []AliasAttributeType `type:"list"`

	// The attributes to be auto-verified. Possible values: email, phone_number.
	AutoVerifiedAttributes []VerifiedAttributeType `type:"list"`

	// The device configuration.
	DeviceConfiguration *DeviceConfigurationType `type:"structure"`

	// The email configuration.
	EmailConfiguration *EmailConfigurationType `type:"structure"`

	// A string representing the email verification message.
	EmailVerificationMessage *string `min:"6" type:"string"`

	// A string representing the email verification subject.
	EmailVerificationSubject *string `min:"1" type:"string"`

	// The Lambda trigger configuration information for the new user pool.
	//
	// In a push model, event sources (such as Amazon S3 and custom applications)
	// need permission to invoke a function. So you will need to make an extra call
	// to add permission for these event sources to invoke your Lambda function.
	//
	// For more information on using the Lambda API to add permission, see AddPermission
	// (https://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html).
	//
	// For adding permission using the AWS CLI, see add-permission (https://docs.aws.amazon.com/cli/latest/reference/lambda/add-permission.html).
	LambdaConfig *LambdaConfigType `type:"structure"`

	// Specifies MFA configuration details.
	MfaConfiguration UserPoolMfaType `type:"string" enum:"true"`

	// The policies associated with the new user pool.
	Policies *UserPoolPolicyType `type:"structure"`

	// A string used to name the user pool.
	//
	// PoolName is a required field
	PoolName *string `min:"1" type:"string" required:"true"`

	// An array of schema attributes for the new user pool. These attributes can
	// be standard or custom attributes.
	Schema []SchemaAttributeType `min:"1" type:"list"`

	// A string representing the SMS authentication message.
	SmsAuthenticationMessage *string `min:"6" type:"string"`

	// The SMS configuration.
	SmsConfiguration *SmsConfigurationType `type:"structure"`

	// A string representing the SMS verification message.
	SmsVerificationMessage *string `min:"6" type:"string"`

	// Used to enable advanced security risk detection. Set the key AdvancedSecurityMode
	// to the value "AUDIT".
	UserPoolAddOns *UserPoolAddOnsType `type:"structure"`

	// The tag keys and values to assign to the user pool. A tag is a label that
	// you can use to categorize and manage user pools in different ways, such as
	// by purpose, owner, environment, or other criteria.
	UserPoolTags map[string]string `type:"map"`

	// Specifies whether email addresses or phone numbers can be specified as usernames
	// when a user signs up.
	UsernameAttributes []UsernameAttributeType `type:"list"`

	// The template for the verification message that the user sees when the app
	// requests permission to access the user's information.
	VerificationMessageTemplate *VerificationMessageTemplateType `type:"structure"`
}

// String returns the string representation
func (s CreateUserPoolInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *CreateUserPoolInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "CreateUserPoolInput"}
	if s.EmailVerificationMessage != nil && len(*s.EmailVerificationMessage) < 6 {
		invalidParams.Add(aws.NewErrParamMinLen("EmailVerificationMessage", 6))
	}
	if s.EmailVerificationSubject != nil && len(*s.EmailVerificationSubject) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("EmailVerificationSubject", 1))
	}

	if s.PoolName == nil {
		invalidParams.Add(aws.NewErrParamRequired("PoolName"))
	}
	if s.PoolName != nil && len(*s.PoolName) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("PoolName", 1))
	}
	if s.Schema != nil && len(s.Schema) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("Schema", 1))
	}
	if s.SmsAuthenticationMessage != nil && len(*s.SmsAuthenticationMessage) < 6 {
		invalidParams.Add(aws.NewErrParamMinLen("SmsAuthenticationMessage", 6))
	}
	if s.SmsVerificationMessage != nil && len(*s.SmsVerificationMessage) < 6 {
		invalidParams.Add(aws.NewErrParamMinLen("SmsVerificationMessage", 6))
	}
	if s.AdminCreateUserConfig != nil {
		if err := s.AdminCreateUserConfig.Validate(); err != nil {
			invalidParams.AddNested("AdminCreateUserConfig", err.(aws.ErrInvalidParams))
		}
	}
	if s.EmailConfiguration != nil {
		if err := s.EmailConfiguration.Validate(); err != nil {
			invalidParams.AddNested("EmailConfiguration", err.(aws.ErrInvalidParams))
		}
	}
	if s.LambdaConfig != nil {
		if err := s.LambdaConfig.Validate(); err != nil {
			invalidParams.AddNested("LambdaConfig", err.(aws.ErrInvalidParams))
		}
	}
	if s.Policies != nil {
		if err := s.Policies.Validate(); err != nil {
			invalidParams.AddNested("Policies", err.(aws.ErrInvalidParams))
		}
	}
	if s.Schema != nil {
		for i, v := range s.Schema {
			if err := v.Validate(); err != nil {
				invalidParams.AddNested(fmt.Sprintf("%s[%v]", "Schema", i), err.(aws.ErrInvalidParams))
			}
		}
	}
	if s.SmsConfiguration != nil {
		if err := s.SmsConfiguration.Validate(); err != nil {
			invalidParams.AddNested("SmsConfiguration", err.(aws.ErrInvalidParams))
		}
	}
	if s.UserPoolAddOns != nil {
		if err := s.UserPoolAddOns.Validate(); err != nil {
			invalidParams.AddNested("UserPoolAddOns", err.(aws.ErrInvalidParams))
		}
	}
	if s.VerificationMessageTemplate != nil {
		if err := s.VerificationMessageTemplate.Validate(); err != nil {
			invalidParams.AddNested("VerificationMessageTemplate", err.(aws.ErrInvalidParams))
		}
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// Represents the response from the server for the request to create a user
// pool.
// Please also see https://docs.aws.amazon.com/goto/WebAPI/cognito-idp-2016-04-18/CreateUserPoolResponse
type CreateUserPoolOutput struct {
	_ struct{} `type:"structure"`

	// A container for the user pool details.
	UserPool *UserPoolType `type:"structure"`
}

// String returns the string representation
func (s CreateUserPoolOutput) String() string {
	return awsutil.Prettify(s)
}

const opCreateUserPool = "CreateUserPool"

// CreateUserPoolRequest returns a request value for making API operation for
// Amazon Cognito Identity Provider.
//
// Creates a new Amazon Cognito user pool and sets the password policy for the
// pool.
//
//    // Example sending a request using CreateUserPoolRequest.
//    req := client.CreateUserPoolRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/cognito-idp-2016-04-18/CreateUserPool
func (c *Client) CreateUserPoolRequest(input *CreateUserPoolInput) CreateUserPoolRequest {
	op := &aws.Operation{
		Name:       opCreateUserPool,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &CreateUserPoolInput{}
	}

	req := c.newRequest(op, input, &CreateUserPoolOutput{})
	return CreateUserPoolRequest{Request: req, Input: input, Copy: c.CreateUserPoolRequest}
}

// CreateUserPoolRequest is the request type for the
// CreateUserPool API operation.
type CreateUserPoolRequest struct {
	*aws.Request
	Input *CreateUserPoolInput
	Copy  func(*CreateUserPoolInput) CreateUserPoolRequest
}

// Send marshals and sends the CreateUserPool API request.
func (r CreateUserPoolRequest) Send(ctx context.Context) (*CreateUserPoolResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &CreateUserPoolResponse{
		CreateUserPoolOutput: r.Request.Data.(*CreateUserPoolOutput),
		response:             &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// CreateUserPoolResponse is the response type for the
// CreateUserPool API operation.
type CreateUserPoolResponse struct {
	*CreateUserPoolOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// CreateUserPool request.
func (r *CreateUserPoolResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
