package awsauthz

import (
	"context"
	"errors"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws/external"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/rs/zerolog/log"
	validator "gopkg.in/go-playground/validator.v9"
)

type AWSAuthenticate struct {
	env               string
	region            string
	orgClient         am.OrganizationService
	systemUserContext am.UserContext
	svc               *cip.CognitoIdentityProvider
	validate          *validator.Validate
}

func New(env, region string, orgClient am.OrganizationService, systemUserContext am.UserContext) *AWSAuthenticate {
	return &AWSAuthenticate{
		env:               env,
		region:            region,
		orgClient:         orgClient,
		systemUserContext: systemUserContext,
		validate:          validator.New(),
	}
}

// Init the aws cip service
func (a *AWSAuthenticate) Init(config []byte) error {
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return err
	}
	cfg.Region = a.region
	a.svc = cip.New(cfg)
	return nil
}

func (a *AWSAuthenticate) getOrgData(ctx context.Context, orgName string) (*am.Organization, error) {
	_, org, err := a.orgClient.Get(ctx, a.systemUserContext, orgName)
	if err != nil {
		return nil, err
	}
	return org, nil
}

func (a *AWSAuthenticate) Login(ctx context.Context, details *authz.LoginDetails) (map[string]string, error) {
	response := make(map[string]string, 0)

	if err := a.validate.Struct(details); err != nil {
		return response, err
	}

	org, err := a.getOrgData(ctx, details.OrgName)
	if err != nil {
		return response, err
	}
	log.Info().Str("username", details.Username).Str("user_pool_id", org.UserPoolID).Str("user_pool_client_id", org.UserPoolAppClientID).Str("org_name", org.OrgName).Msg("got organization data")
	input := &cip.AdminInitiateAuthInput{
		AuthFlow:       cip.AuthFlowTypeAdminNoSrpAuth,
		AuthParameters: map[string]string{"USERNAME": details.Username, "PASSWORD": details.Password},
		ClientId:       aws.String(org.UserPoolAppClientID),
		UserPoolId:     aws.String(org.UserPoolID),
	}

	req := a.svc.AdminInitiateAuthRequest(input)
	out, err := req.Send()
	if err != nil {
		return response, err
	}

	if out.ChallengeName == cip.ChallengeNameTypeNewPasswordRequired {
		response["state"] = authz.AuthNewPasswordRequired
		return response, nil
	}

	if out.AuthenticationResult == nil {
		return response, errors.New("empty authentication result")
	}
	response["state"] = authz.AuthSuccess
	response["AccessToken"] = *out.AuthenticationResult.AccessToken
	response["IdToken"] = *out.AuthenticationResult.IdToken
	response["RefreshToken"] = *out.AuthenticationResult.RefreshToken
	response["Expires"] = strconv.FormatInt(*out.AuthenticationResult.ExpiresIn, 10)
	response["TokenType"] = *out.AuthenticationResult.TokenType
	return response, nil
}

// SetNewPassword for when a user first logs in and needs to set their new password.
// Instead of requiring us to send / expose the session & UID, we simply re-issue the flow but this time
// capture the challenge and provide the new password.
func (a *AWSAuthenticate) SetNewPassword(ctx context.Context, details *authz.LoginDetails) (map[string]string, error) {
	response := make(map[string]string, 0)

	if err := a.validate.Struct(details); err != nil {
		return response, err
	}

	org, err := a.getOrgData(ctx, details.OrgName)
	if err != nil {
		return response, err
	}

	input := &cip.AdminInitiateAuthInput{
		AuthFlow:       cip.AuthFlowTypeAdminNoSrpAuth,
		AuthParameters: map[string]string{"USERNAME": details.Username, "PASSWORD": details.Password},
		ClientId:       aws.String(org.UserPoolAppClientID),
		UserPoolId:     aws.String(org.UserPoolID),
	}

	req := a.svc.AdminInitiateAuthRequest(input)
	out, err := req.Send()
	if err != nil {
		return response, err
	}

	// odd they can just login normally.
	if out.AuthenticationResult != nil {
		response["state"] = authz.AuthInvalidRequest
		return response, nil
	}
	newPassParams := make(map[string]string, 0)
	newPassParams["USERNAME"] = out.ChallengeParameters["USER_ID_FOR_SRP"]
	newPassParams["NEW_PASSWORD"] = details.NewPassword

	newPass := &cip.AdminRespondToAuthChallengeInput{
		ChallengeName:      cip.ChallengeNameTypeNewPasswordRequired,
		ChallengeResponses: newPassParams,
		Session:            out.Session,
		ClientId:           aws.String(org.UserPoolAppClientID),
		UserPoolId:         aws.String(org.UserPoolID),
	}

	newReq := a.svc.AdminRespondToAuthChallengeRequest(newPass)
	challenge, err := newReq.Send()
	if err != nil {
		return response, err
	}

	if challenge.ChallengeName == cip.ChallengeNameTypeNewPasswordRequired || challenge.AuthenticationResult == nil {
		response["state"] = authz.AuthInvalidNewPassword
		return response, errors.New("failed to set new password")
	}

	response["state"] = "AUTHENTICATED"
	response["AccessToken"] = *challenge.AuthenticationResult.AccessToken
	response["IdToken"] = *challenge.AuthenticationResult.IdToken
	response["RefreshToken"] = *challenge.AuthenticationResult.RefreshToken
	response["Expires"] = strconv.FormatInt(*challenge.AuthenticationResult.ExpiresIn, 10)
	response["TokenType"] = *challenge.AuthenticationResult.TokenType
	return response, nil
}

func (a *AWSAuthenticate) Forgot(ctx context.Context, details *authz.ResetDetails) error {
	if err := a.validate.Struct(details); err != nil {
		return err
	}

	org, err := a.getOrgData(ctx, details.OrgName)
	if err != nil {
		return err
	}

	input := &cip.ForgotPasswordInput{
		Username: aws.String(details.Username),
		ClientId: aws.String(org.UserPoolAppClientID),
	}

	req := a.svc.ForgotPasswordRequest(input)
	_, err = req.Send()
	return err
}

func (a *AWSAuthenticate) Reset(ctx context.Context, details *authz.ResetDetails) error {
	if err := a.validate.Struct(details); err != nil {
		return err
	}

	org, err := a.getOrgData(ctx, details.OrgName)
	if err != nil {
		return err
	}

	input := &cip.ConfirmForgotPasswordInput{
		Username:         aws.String(details.Username),
		ConfirmationCode: aws.String(details.VerificationCode),
		Password:         aws.String(details.Password),
		ClientId:         aws.String(org.UserPoolAppClientID),
	}

	req := a.svc.ConfirmForgotPasswordRequest(input)
	_, err = req.Send()

	return err
}

func (a *AWSAuthenticate) Logout(ctx context.Context, details *authz.UserDetails) error {
	return nil
}
