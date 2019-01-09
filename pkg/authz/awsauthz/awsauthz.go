package awsauthz

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/linkai-io/frontend/pkg/token"
	"github.com/linkai-io/frontend/pkg/token/awstoken"
	"github.com/rs/zerolog/log"
	validator "gopkg.in/go-playground/validator.v9"
)

type AWSAuthenticate struct {
	env         string
	region      string
	orgClient   am.OrganizationService
	userContext am.UserContext
	svc         *cip.CognitoIdentityProvider
	validate    *validator.Validate
	tokener     token.Tokener
}

func New(env, region string, orgClient am.OrganizationService, userContext am.UserContext) *AWSAuthenticate {
	return &AWSAuthenticate{
		env:         env,
		region:      region,
		orgClient:   orgClient,
		userContext: userContext,
		validate:    validator.New(),
		tokener:     awstoken.New(env, region),
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
	_, org, err := a.orgClient.Get(ctx, a.userContext, orgName)
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
		log.Error().Err(err).Str("org_name", org.OrgName).Str("username", details.Username).Msg("authentication failure")
		return response, err
	}

	if out.ChallengeName == cip.ChallengeNameTypeNewPasswordRequired {
		response["state"] = authz.AuthNewPasswordRequired
		return response, nil
	}

	if out.AuthenticationResult == nil {
		return response, errors.New("empty authentication result")
	}

	return a.successMap(out.AuthenticationResult)
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

	return a.successMap(challenge.AuthenticationResult)
}

// Refresh token flow when id token has expired and needs to be refreshed
func (a *AWSAuthenticate) Refresh(ctx context.Context, details *authz.TokenDetails) (map[string]string, error) {
	response := make(map[string]string, 0)

	if err := a.validate.Struct(details); err != nil {
		return response, err
	}

	// it's OK to call unsafe extract here because even if they 'refresh' a token they control (from their own userpool)
	// the authorizer lambda checks the signature against a valid JWK which we have stored in our DB for the organization name
	// also, the token will fail validation because it's expired so, *shrug*
	accessToken, err := a.tokener.UnsafeExtractAccess(ctx, details.AccessToken)
	if err != nil {
		return response, err
	}

	userPool := strings.Replace(accessToken.StandardClaims.Issuer, fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/", a.region), "", -1)

	input := &cip.AdminInitiateAuthInput{
		AuthFlow:       cip.AuthFlowTypeRefreshTokenAuth,
		AuthParameters: map[string]string{"REFRESH_TOKEN": details.RefreshToken},
		ClientId:       aws.String(accessToken.ClientID),
		UserPoolId:     aws.String(userPool),
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

	return a.successMap(out.AuthenticationResult)
}

// Forgot password flow
func (a *AWSAuthenticate) Forgot(ctx context.Context, details *authz.ResetDetails) error {
	if err := a.validate.Struct(details); err != nil {
		return err
	}
	log.Info().Msg("calling getOrgData in forgot")
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

// Reset password flow
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

func (a *AWSAuthenticate) successMap(authResult *cip.AuthenticationResultType) (map[string]string, error) {
	response := make(map[string]string, 5)
	response["state"] = authz.AuthSuccess
	response["access_token"] = *authResult.AccessToken
	response["id_token"] = *authResult.IdToken
	response["refresh_token"] = *authResult.RefreshToken
	response["expires"] = strconv.FormatInt(*authResult.ExpiresIn, 10)
	response["token_type"] = *authResult.TokenType

	return response, nil
}
