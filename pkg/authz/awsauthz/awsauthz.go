package awsauthz

import (
	"context"
	"errors"
	"log"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws/external"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/authz"
)

type AWSAuthenticate struct {
	env               string
	region            string
	orgClient         am.OrganizationService
	systemUserContext am.UserContext
	svc               *cip.CognitoIdentityProvider
}

func New(env, region string, orgClient am.OrganizationService, systemUserContext am.UserContext) *AWSAuthenticate {
	return &AWSAuthenticate{env: env, region: region, orgClient: orgClient, systemUserContext: systemUserContext}
}

func (a *AWSAuthenticate) Init(config []byte) error {
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return err
	}
	cfg.Region = a.env
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

	if out.ChallengeName == cip.ChallengeNameTypeNewPasswordRequired {
		response["uid"] = out.ChallengeParameters["USER_ID_FOR_SRP"]
		response["session"] = *out.Session
		return response, nil
	}

	if out.AuthenticationResult == nil {
		return response, errors.New("empty authentication result")
	}

	response["AccessToken"] = *out.AuthenticationResult.AccessToken
	response["IdToken"] = *out.AuthenticationResult.IdToken
	response["RefreshToken"] = *out.AuthenticationResult.RefreshToken
	response["Expires"] = strconv.FormatInt(*out.AuthenticationResult.ExpiresIn, 10)
	response["TokenType"] = *out.AuthenticationResult.TokenType
	return response, nil
}

func (a *AWSAuthenticate) ChangePwd(ctx context.Context, details *authz.LoginDetails) error {
	return nil
}

func (a *AWSAuthenticate) Forgot(ctx context.Context, details *authz.ResetDetails) error {
	params := make(map[string]string, 0)
	params["USERNAME"] = "isaac.dawson@linkai.io"
	//params["PASSWORD"] = "somenewpassword." //"8tv;;qHzZX"
	input := &cip.ForgotPasswordInput{
		Username: aws.String("isaac.dawson@linkai.io"),
		ClientId: aws.String("6bjp2k79is6ra7504e3rik163j"),
	}
	req := a.svc.ForgotPasswordRequest(input)
	out, err := req.Send()
	if err != nil {
		return err
	}
	log.Printf("out: %#v\n", out)
	return nil
}

func (a *AWSAuthenticate) Reset(ctx context.Context, details *authz.ResetDetails) error {
	params := make(map[string]string, 0)
	params["USERNAME"] = "isaac.dawson@linkai.io"
	//params["PASSWORD"] = "somenewpassword." //"8tv;;qHzZX"
	input := &cip.ConfirmForgotPasswordInput{
		Username:         aws.String("isaac.dawson@linkai.io"),
		ConfirmationCode: aws.String("189692"),
		Password:         aws.String("somenewpassword2."),
		//AuthParameters: params,
		ClientId: aws.String("6bjp2k79is6ra7504e3rik163j"),
		//UserPoolId:     aws.String("us-east-1_BRlOXjA4M"),
	}
	req := a.svc.ConfirmForgotPasswordRequest(input)
	out, err := req.Send()
	if err != nil {
		return err
	}
	log.Printf("out: %#v\n", out)
	return nil
}

func (a *AWSAuthenticate) Logout(ctx context.Context, details *authz.UserDetails) error {
	return nil
}
