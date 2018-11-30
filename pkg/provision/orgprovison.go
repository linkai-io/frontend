package provision

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	identity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/linkai-io/am/am"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	URLFmt            = "https://%s-auth.linkai.io/"
	LogoutURLFmt      = "https://%s-console.linkai.io/logout"
	LoginURLFmt       = "https://%s-console.linkai.io/dashboard/"
	WelcomeTitleMsg   = `Welcome to linkai.io's hakken web management system`
	WelcomeSubjectMsg = `Hello %s,<br>
Your organization has been successfully created, please login to the hakken web management system at: %s<br>
Your username is: {username}<br>
Your temporary password is: {####}<br>
<br><br>
Thank you,<br>
The linkai.io team`
)

type OrgProvisoner struct {
	orgClient  am.OrganizationService
	env        string
	region     string
	serviceURL string
	loginURL   string
	logoutURL  string
	svc        *cip.CognitoIdentityProvider
	fedSvc     *identity.CognitoIdentity
}

func NewOrgProvisoner(env, region string, orgClient am.OrganizationService) *OrgProvisoner {
	p := &OrgProvisoner{orgClient: orgClient}
	p.env = env
	p.region = region
	cfg, _ := external.LoadDefaultAWSConfig()
	cfg.Region = p.region

	p.createURLS()

	p.svc = cip.New(cfg)
	p.fedSvc = identity.New(cfg)
	return p
}

func (p *OrgProvisoner) createURLS() {
	p.serviceURL = fmt.Sprintf(URLFmt, p.env)
	p.loginURL = fmt.Sprintf(LoginURLFmt, p.env)
	p.logoutURL = fmt.Sprintf(LogoutURLFmt, p.env)

	if p.env == "prod" {
		p.serviceURL = fmt.Sprintf("https://auth.linkai.io/")
		p.loginURL = fmt.Sprintf("https://console.linka.io/dashboard/")
		p.logoutURL = fmt.Sprintf("https://console.linkai.io/logout")
	}
}

// orgExists checks our organization service to see if the organization already exists. This is bad if new organization,
// good if support account
func (p *OrgProvisoner) orgExists(ctx context.Context, userContext am.UserContext, orgData *am.Organization) (bool, error) {
	var err error
	var org *am.Organization

	// check if exists
	_, org, err = p.orgClient.Get(ctx, userContext, orgData.OrgName)
	return (org != nil), err
}

// AddSupportOrganization to manage the hakken service (provision, troubleshoot etc)
func (p *OrgProvisoner) AddSupportOrganization(ctx context.Context, userContext am.UserContext, orgData *am.Organization, password string) error {
	var err error
	exists, err := p.orgExists(ctx, userContext, orgData)
	if exists == false || err != nil {
		return err
	}
	return p.add(ctx, userContext, orgData, password)
}

// Add an organization to hakken provided the organization does not already exist.
func (p *OrgProvisoner) Add(ctx context.Context, userContext am.UserContext, orgData *am.Organization) error {
	var err error
	exists, err := p.orgExists(ctx, userContext, orgData)
	if exists == true || err != nil {
		return errors.Wrap(err, "org exists or error")
	}
	return p.add(ctx, userContext, orgData, "")
}

func (p *OrgProvisoner) add(ctx context.Context, userContext am.UserContext, orgData *am.Organization, password string) error {
	var err error

	// create user pool
	orgData.UserPoolID, err = p.createUserPool(ctx, orgData)
	if err != nil {
		return err
	}
	log.Info().Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("user pool successfully created")

	// create app client
	orgData.UserPoolAppClientID, orgData.UserPoolAppClientSecret, err = p.createAppClient(ctx, orgData)
	if err != nil {
		if deleteErr := p.deleteUserPool(ctx, orgData); err != nil {
			log.Error().Err(deleteErr).Msg("failed to delete user pool")
		}
		return err
	}
	log.Info().Str("orgname", orgData.OrgName).Str("user_app_client_id", orgData.UserPoolAppClientID).Msg("user pool app client successfully created")

	// create identity pool
	orgData.IdentityPoolID, err = p.createIdentityPool(ctx, orgData)
	if err != nil {
		if deleteErr := p.deleteUserPool(ctx, orgData); err != nil {
			log.Error().Err(deleteErr).Msg("failed to delete user pool")
		}
		return err
	}
	log.Info().Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("user pool appclient successfully created")

	// create initial user
	err = p.createOwnerUser(ctx, orgData)
	if err != nil {
		if deleteErr := p.deleteIdentityPool(ctx, orgData); deleteErr != nil {
			log.Error().Err(deleteErr).Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("failed to delete identity pool")
		}
		if deleteErr := p.deleteUserPool(ctx, orgData); deleteErr != nil {
			log.Error().Err(deleteErr).Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("failed to delete user pool")
		}
		return err
	}
	return err
}

func (p *OrgProvisoner) createUserPool(ctx context.Context, orgData *am.Organization) (string, error) {
	userPool := &cip.CreateUserPoolInput{
		AdminCreateUserConfig: &cip.AdminCreateUserConfigType{
			AllowAdminCreateUserOnly:  aws.Bool(true),
			UnusedAccountValidityDays: aws.Int64(5),
			InviteMessageTemplate: &cip.MessageTemplateType{
				EmailSubject: aws.String(WelcomeTitleMsg),
				EmailMessage: aws.String(fmt.Sprintf(WelcomeSubjectMsg, orgData.FirstName, p.serviceURL)),
			},
		},
		EmailVerificationSubject: aws.String(WelcomeTitleMsg),
		EmailVerificationMessage: aws.String(fmt.Sprintf(WelcomeSubjectMsg, orgData.FirstName, p.serviceURL)),
		PoolName:                 aws.String("org-linkai-" + orgData.OrgName),
		UsernameAttributes:       []cip.UsernameAttributeType{"email"},
		MfaConfiguration:         cip.UserPoolMfaTypeOff,
		AutoVerifiedAttributes:   []cip.VerifiedAttributeType{"email"},
		Policies: &cip.UserPoolPolicyType{
			PasswordPolicy: &cip.PasswordPolicyType{
				MinimumLength:    aws.Int64(10),
				RequireLowercase: aws.Bool(false),
				RequireNumbers:   aws.Bool(false),
				RequireSymbols:   aws.Bool(false),
			},
		},
		VerificationMessageTemplate: &cip.VerificationMessageTemplateType{
			EmailSubject: aws.String(WelcomeTitleMsg),
			//EmailSubjectByLink: aws.String(WelcomeTitleMsg),
			EmailMessage: aws.String(fmt.Sprintf(WelcomeSubjectMsg, orgData.FirstName, p.serviceURL)),
			//EmailMessageByLink: aws.String(fmt.Sprintf(WelcomeSubjectMsg, p.serviceURL)),
			DefaultEmailOption: cip.DefaultEmailOptionTypeConfirmWithCode,
		},
		Schema: p.userPoolAttributeSchema(),
	}
	req := p.svc.CreateUserPoolRequest(userPool)
	out, err := req.Send()
	if err != nil {
		poolErr := checkError("create_user_pool", err)
		return "", poolErr
	}

	return *out.UserPool.Id, nil
}

func (p *OrgProvisoner) userPoolAttributeSchema() []cip.SchemaAttributeType {
	var strType cip.AttributeDataType
	var numType cip.AttributeDataType

	strType = "String"
	numType = "Number"

	schema := make([]cip.SchemaAttributeType, 0)
	// add orgname custom attribute
	schema = append(schema, cip.SchemaAttributeType{
		AttributeDataType: strType,
		Mutable:           aws.Bool(false),
		Name:              aws.String("orgname"),
		StringAttributeConstraints: &cip.StringAttributeConstraintsType{
			MinLength: aws.String("3"),
			MaxLength: aws.String("256"),
		},
	})
	// add org role custom developer only attribute
	schema = append(schema, cip.SchemaAttributeType{
		AttributeDataType:      strType,
		Mutable:                aws.Bool(true),
		DeveloperOnlyAttribute: aws.Bool(true),
		Name:                   aws.String("role"),
		StringAttributeConstraints: &cip.StringAttributeConstraintsType{
			MinLength: aws.String("3"),
			MaxLength: aws.String("256"),
		},
	})

	// add org subscription level custom developer only attribute
	schema = append(schema, cip.SchemaAttributeType{
		AttributeDataType:      numType,
		Mutable:                aws.Bool(true),
		DeveloperOnlyAttribute: aws.Bool(true),
		Name:                   aws.String("subscription"),
		NumberAttributeConstraints: &cip.NumberAttributeConstraintsType{
			MinValue: aws.String("1"),
			MaxValue: aws.String("1000"),
		},
	})

	// add required attributes (email, firstname / lastname)
	for _, attr := range []string{"email", "family_name", "given_name"} {
		schema = append(schema, cip.SchemaAttributeType{
			AttributeDataType: strType,
			Required:          aws.Bool(true),
			Name:              aws.String(attr),
		})
	}

	return schema
}

func (p *OrgProvisoner) createAppClient(ctx context.Context, orgData *am.Organization) (string, string, error) {

	appClient := &cip.CreateUserPoolClientInput{
		UserPoolId:                 aws.String(orgData.UserPoolID),
		ClientName:                 aws.String("org_linkai_client_" + orgData.OrgName),
		GenerateSecret:             aws.Bool(true),
		LogoutURLs:                 []string{p.logoutURL},
		CallbackURLs:               []string{p.loginURL},
		DefaultRedirectURI:         aws.String(p.loginURL),
		ReadAttributes:             []string{"email", "family_name", "given_name", "custom:orgname"},
		WriteAttributes:            []string{"email", "family_name", "given_name"},
		RefreshTokenValidity:       aws.Int64(30),
		SupportedIdentityProviders: []string{"COGNITO"},
	}
	req := p.svc.CreateUserPoolClientRequest(appClient)
	out, err := req.Send()
	if err != nil {
		appClientErr := checkError("create_app_client", err)
		return "", "", appClientErr
	}
	return *out.UserPoolClient.ClientId, *out.UserPoolClient.ClientSecret, nil
}

func (p *OrgProvisoner) createIdentityPool(ctx context.Context, orgData *am.Organization) (string, error) {
	providerName := fmt.Sprintf("cognito-idp.%s.amazonaws.com/%s", p.region, orgData.UserPoolID)

	providers := make([]identity.Provider, 0)
	providers = append(providers, identity.Provider{
		ClientId:             aws.String(orgData.UserPoolAppClientID),
		ProviderName:         aws.String(providerName),
		ServerSideTokenCheck: aws.Bool(true),
	})

	identityPool := &identity.CreateIdentityPoolInput{
		IdentityPoolName:               aws.String("org_linkai_identity_pool_" + strings.Replace(orgData.OrgName, "-", "_", -1)),
		AllowUnauthenticatedIdentities: aws.Bool(false),
		CognitoIdentityProviders:       providers,
	}

	req := p.fedSvc.CreateIdentityPoolRequest(identityPool)
	out, err := req.Send()
	if err != nil {
		identityErr := checkError("create_app_client", err)
		return "", identityErr
	}

	return *out.IdentityPoolId, nil
}

func (p *OrgProvisoner) createOwnerUser(ctx context.Context, orgData *am.Organization) error {
	user := &cip.AdminCreateUserInput{
		DesiredDeliveryMediums: []cip.DeliveryMediumType{"EMAIL"},
		UserAttributes: []cip.AttributeType{
			cip.AttributeType{
				Name:  aws.String("email"),
				Value: aws.String(orgData.OwnerEmail),
			},
			cip.AttributeType{
				Name:  aws.String("given_name"),
				Value: aws.String(orgData.FirstName),
			},
			cip.AttributeType{
				Name:  aws.String("family_name"),
				Value: aws.String(orgData.LastName),
			},
			cip.AttributeType{
				Name:  aws.String("dev:custom:role"),
				Value: aws.String("owner"),
			},
			cip.AttributeType{
				Name:  aws.String("dev:custom:subscription"),
				Value: aws.String(strconv.Itoa(orgData.SubscriptionID)),
			},
			cip.AttributeType{
				Name:  aws.String("custom:orgname"),
				Value: aws.String(orgData.OrgName),
			},
		},
		UserPoolId: aws.String(orgData.UserPoolID),
		Username:   aws.String(orgData.OwnerEmail),
	}
	req := p.svc.AdminCreateUserRequest(user)
	_, err := req.Send()
	return err
}

// Delete the identity pool and user
func (p *OrgProvisoner) Delete(ctx context.Context, orgData *am.Organization) error {
	if deleteErr := p.deleteIdentityPool(ctx, orgData); deleteErr != nil {
		return deleteErr
	}
	if deleteErr := p.deleteUserPool(ctx, orgData); deleteErr != nil {
		return deleteErr
	}
	return nil
}

func (p *OrgProvisoner) deleteUserPool(ctx context.Context, orgData *am.Organization) error {
	input := &cip.DeleteUserPoolInput{
		UserPoolId: aws.String(orgData.UserPoolID),
	}

	req := p.svc.DeleteUserPoolRequest(input)
	_, err := req.Send()
	if err != nil {
		return err
	}
	return nil
}

func (p *OrgProvisoner) deleteIdentityPool(ctx context.Context, orgData *am.Organization) error {
	input := &identity.DeleteIdentityPoolInput{
		IdentityPoolId: aws.String(orgData.IdentityPoolID),
	}
	req := p.fedSvc.DeleteIdentityPoolRequest(input)
	_, err := req.Send()
	if err != nil {
		return err
	}
	return nil
}

func (p *OrgProvisoner) List() (map[string]*am.Organization, error) {
	return nil, nil
}

func checkError(action string, err error) error {
	if awsErr, ok := err.(awserr.Error); ok {
		// Get error details
		log.Error().Err(awsErr).Str("aws_code", awsErr.Code()).Str("aws_message", awsErr.Message()).Str("action", action)
		return awsErr
	}
	return err
}
