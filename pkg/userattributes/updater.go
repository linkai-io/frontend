package userattributes

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws/external"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/linkai-io/am/am"
)

type Updater struct {
	env    string
	region string
	svc    *cip.CognitoIdentityProvider
}

func New(env, region string) *Updater {
	return &Updater{env: env, region: region}
}

func (u *Updater) Init() error {
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return err
	}
	cfg.Region = u.region
	u.svc = cip.New(cfg)
	return nil
}

func (u *Updater) Update(ctx context.Context, userContext am.UserContext, user am.User) error {
	input := &cip.AdminUpdateUserAttributesInput{
		UserAttributes: nil,
		UserPoolId:     nil,
		Username:       nil,
	}
	req := u.svc.AdminUpdateUserAttributesRequest(input)
	_, err := req.Send(ctx)
	return err
}
