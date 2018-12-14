package provision

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	identity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/linkai-io/am/am"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	URLFmt            = "https://%sconsole.linkai.io/"
	ResetURLFmt       = "https://%sconsole.linkai.io/auth/reset"
	LogoutURLFmt      = "https://%sconsole.linkai.io/logout"
	LoginURLFmt       = "https://%sconsole.linkai.io/dashboard/"
	WelcomeTitleMsg   = `Welcome to linkai.io's hakken web management system`
	WelcomeSubjectMsg = `Hello %s,<br>
Your organization has been successfully created, please login to the hakken web management system at: %s<br>
Your organization name is: %s<br>
Your username is: {username}<br>
Your temporary password is: {####}<br>
<br><br>
Thank you,<br>
The linkai.io team`

	VerificationTitleMsg   = `Verification required for linkai.io's hakken web management system`
	VerificationSubjectMsg = `Hello,<br>
Someone has requested a password reset for this account. If this is you, please go to 
%s and fill out the necessary details to reset your password.<br>
<br>
Your organization name is: %s<br>
Your temporary reset code is: {####}<br>
<br>
Thank you,<br>
The linkai.io team`
)

// OrgProvisioner for provisioning support and customer organizations
type OrgProvisioner struct {
	orgClient  am.OrganizationService
	env        string
	region     string
	serviceURL string
	loginURL   string
	logoutURL  string
	resetURL   string
	svc        *cip.CognitoIdentityProvider
	fedSvc     *identity.CognitoIdentity
}

func NewOrgProvisioner(env, region string, orgClient am.OrganizationService) *OrgProvisioner {
	p := &OrgProvisioner{orgClient: orgClient}
	p.env = env
	p.region = region
	cfg, _ := external.LoadDefaultAWSConfig()
	cfg.Region = p.region

	p.createURLS()

	p.svc = cip.New(cfg)
	p.fedSvc = identity.New(cfg)
	return p
}

func (p *OrgProvisioner) createURLS() {
	var env string

	if p.env != "prod" {
		env = p.env + "-"
	}
	p.serviceURL = fmt.Sprintf(URLFmt, env)
	p.loginURL = fmt.Sprintf(LoginURLFmt, env)
	p.logoutURL = fmt.Sprintf(LogoutURLFmt, env)
	p.resetURL = fmt.Sprintf(ResetURLFmt, env)
}

// orgExists checks our organization service to see if the organization already exists. This is bad if new organization,
// good if support account
func (p *OrgProvisioner) orgExists(ctx context.Context, userContext am.UserContext, orgData *am.Organization) (*am.Organization, error) {
	var err error
	var org *am.Organization

	// check if exists
	_, org, err = p.orgClient.Get(ctx, userContext, orgData.OrgName)
	return org, err
}

// AddSupportOrganization to manage the hakken service (provision, troubleshoot etc)
// TODO: Need to look up support userID by modifying UserService to allow looking up non-same-org users
func (p *OrgProvisioner) AddSupportOrganization(ctx context.Context, userContext am.UserContext, orgData *am.Organization, roles map[string]string, password string) (string, string, error) {
	var err error
	supportOrg, err := p.orgExists(ctx, userContext, orgData)
	if supportOrg == nil {
		log.Error().Err(err).Str("org_name", orgData.OrgName).Msg("failed to find support organization")
		return "", "", errors.New("support organization does not exist")
	}

	if err != nil {
		return "", "", err
	}

	supportOrg.FirstName = orgData.FirstName
	supportOrg.LastName = orgData.LastName
	supportOrg.OwnerEmail = orgData.OwnerEmail

	// add cognito pools/clients
	if err := p.add(ctx, supportOrg, roles, password); err != nil {
		return "", "", err
	}

	// change to support user context so we don't overwrite system. Update will
	// use the OrgID from context to determine which org to update
	supportUserContext := &am.UserContextData{
		OrgID:  supportOrg.OrgID,
		UserID: supportOrg.OrgID, // TODO: This assumes orgID == userID (which it almost always does) but should get from UserService
	}

	if err := p.getUserPoolJWK(ctx, supportOrg); err != nil {
		p.cleanUp(ctx, supportOrg)
		return "", "", err
	}

	// adds all user pool/identity pool related information to the support organization.
	_, err = p.orgClient.Update(ctx, supportUserContext, supportOrg)
	if err != nil {
		p.cleanUp(ctx, supportOrg)
		return "", "", err
	}

	log.Info().Str("user_pool_id", supportOrg.UserPoolID).Str("identity_pool_id", supportOrg.IdentityPoolID).Msg("returning success")
	return supportOrg.UserPoolID, supportOrg.IdentityPoolID, nil
}

func (p *OrgProvisioner) getUserPoolJWK(ctx context.Context, supportOrg *am.Organization) error {
	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", p.region, supportOrg.UserPoolID)
	myClient := &http.Client{Timeout: 10 * time.Second}
	r, err := myClient.Get(jwksURL)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	supportOrg.UserPoolJWK = string(data)
	if supportOrg.UserPoolJWK == "" {
		return errors.New("jwk for user pool was empty")
	}
	return nil
}

// Add an organization to hakken provided the organization does not already exist.
func (p *OrgProvisioner) Add(ctx context.Context, userContext am.UserContext, orgData *am.Organization, roles map[string]string) error {
	var err error
	org, err := p.orgExists(ctx, userContext, orgData)
	if org != nil || err != nil {
		return errors.Wrap(err, "org exists or error")
	}
	return p.add(ctx, orgData, roles, "")
}

// This method provisions everything an organization needs to get running:
// 1. A user pool
// 2. User pool groups
// 3. A user pool App Client
// 4. Identity Pool (sets roles too)
// 5. The owner user
// 6. Assigns owner user to owner group
func (p *OrgProvisioner) add(ctx context.Context, orgData *am.Organization, roles map[string]string, password string) error {
	var err error

	// create user pool
	orgData.UserPoolID, err = p.createUserPool(ctx, orgData)
	if err != nil {
		return err
	}
	log.Info().Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("user pool successfully created")

	if err := p.createPoolGroups(ctx, orgData, roles); err != nil {
		p.cleanUp(ctx, orgData)
		return err
	}
	// create app client
	orgData.UserPoolAppClientID, err = p.createAppClient(ctx, orgData)
	if err != nil {
		p.cleanUp(ctx, orgData)
		return err
	}
	log.Info().Str("orgname", orgData.OrgName).Str("user_app_client_id", orgData.UserPoolAppClientID).Msg("user pool app client successfully created")

	// create identity pool and set auth/unauth roles
	orgData.IdentityPoolID, err = p.createIdentityPool(ctx, orgData, roles)
	if err != nil {
		p.cleanUp(ctx, orgData)
		return err
	}

	log.Info().Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Str("identity_pool_id", orgData.IdentityPoolID).Msg("identity pool successfully created")

	// create initial user and assign user to owner group
	err = p.createOwnerUser(ctx, orgData, password)
	if err != nil {
		p.cleanUp(ctx, orgData)
		return err
	}

	log.Info().Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Str("identity_pool_id", orgData.IdentityPoolID).Msg("owner user successfully created")

	return err
}

func (p *OrgProvisioner) createUserPool(ctx context.Context, orgData *am.Organization) (string, error) {
	poolName := aws.String("org-linkai-" + orgData.OrgName)

	if exists := p.checkUserPoolExists(*poolName, ""); exists {
		return "", errors.New("userpool already exists")
	}

	userPool := &cip.CreateUserPoolInput{
		AdminCreateUserConfig: &cip.AdminCreateUserConfigType{
			AllowAdminCreateUserOnly:  aws.Bool(true),
			UnusedAccountValidityDays: aws.Int64(5),
			InviteMessageTemplate: &cip.MessageTemplateType{
				EmailSubject: aws.String(WelcomeTitleMsg),
				EmailMessage: aws.String(fmt.Sprintf(WelcomeSubjectMsg, orgData.FirstName, p.serviceURL, orgData.OrgName)),
			},
		},
		EmailVerificationSubject: aws.String(WelcomeTitleMsg),
		EmailVerificationMessage: aws.String(fmt.Sprintf(WelcomeSubjectMsg, orgData.FirstName, p.serviceURL, orgData.OrgName)),
		PoolName:                 poolName,
		UsernameAttributes:       []cip.UsernameAttributeType{"email"},
		MfaConfiguration:         cip.UserPoolMfaTypeOff,
		AutoVerifiedAttributes:   []cip.VerifiedAttributeType{cip.VerifiedAttributeTypeEmail},
		Policies: &cip.UserPoolPolicyType{
			PasswordPolicy: &cip.PasswordPolicyType{
				MinimumLength:    aws.Int64(10),
				RequireLowercase: aws.Bool(false),
				RequireNumbers:   aws.Bool(false),
				RequireSymbols:   aws.Bool(false),
			},
		},
		VerificationMessageTemplate: &cip.VerificationMessageTemplateType{
			EmailSubject:       aws.String(VerificationTitleMsg),
			EmailMessage:       aws.String(fmt.Sprintf(VerificationSubjectMsg, p.resetURL, orgData.OrgName)),
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
	log.Info().Str("user_pool_id", *out.UserPool.Id).Msg("userpool created")
	return *out.UserPool.Id, nil
}

func (p *OrgProvisioner) checkUserPoolExists(name, token string) bool {

	input := &cip.ListUserPoolsInput{
		MaxResults: aws.Int64(50),
	}

	if token != "" {
		input.NextToken = aws.String(token)
	}

	req := p.svc.ListUserPoolsRequest(input)
	out, err := req.Send()
	if err != nil {
		return false
	}

	if out == nil {
		return false
	}

	for _, v := range out.UserPools {
		if *v.Name == name {
			return true
		}
	}

	if out.NextToken != nil && *out.NextToken != "" {
		return p.checkUserPoolExists(name, *out.NextToken)
	}

	return false
}

func (p *OrgProvisioner) userPoolAttributeSchema() []cip.SchemaAttributeType {
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
			MaxValue: aws.String("10000"),
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

func (p *OrgProvisioner) createPoolGroups(ctx context.Context, orgData *am.Organization, roles map[string]string) error {

	for k, v := range roles {
		// don't add the identity pool roles to a group
		if k == "authenticated" || k == "unauthenticated" {
			continue
		}

		input := &cip.CreateGroupInput{
			Description: aws.String(k),
			GroupName:   aws.String(k),
			RoleArn:     aws.String(v),
			UserPoolId:  aws.String(orgData.UserPoolID),
		}
		log.Info().Str("user_pool_id", orgData.UserPoolID).Str("group_name", k).Str("role_arn", v).Msg("creating group")
		req := p.svc.CreateGroupRequest(input)
		_, err := req.Send()
		if err != nil {
			checkError("create_pool_groups", err)
			return errors.Wrap(err, "failed to create organization user pool group")
		}
	}
	return nil
}

func (p *OrgProvisioner) createAppClient(ctx context.Context, orgData *am.Organization) (string, error) {

	appClient := &cip.CreateUserPoolClientInput{
		UserPoolId:                 aws.String(orgData.UserPoolID),
		ClientName:                 aws.String("org_linkai_client_" + orgData.OrgName),
		GenerateSecret:             aws.Bool(false),
		LogoutURLs:                 []string{p.logoutURL},
		CallbackURLs:               []string{p.loginURL},
		DefaultRedirectURI:         aws.String(p.loginURL),
		ExplicitAuthFlows:          []cip.ExplicitAuthFlowsType{cip.ExplicitAuthFlowsTypeAdminNoSrpAuth},
		ReadAttributes:             []string{"email", "family_name", "given_name", "custom:orgname"},
		WriteAttributes:            []string{"email", "family_name", "given_name"},
		RefreshTokenValidity:       aws.Int64(30),
		SupportedIdentityProviders: []string{"COGNITO"},
	}
	req := p.svc.CreateUserPoolClientRequest(appClient)
	out, err := req.Send()
	if err != nil {
		appClientErr := checkError("create_app_client", err)
		return "", appClientErr
	}
	return *out.UserPoolClient.ClientId, nil
}

func (p *OrgProvisioner) createIdentityPool(ctx context.Context, orgData *am.Organization, roles map[string]string) (string, error) {
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
		identityErr := checkError("create_identity_pool", err)
		return "", identityErr
	}

	log.Info().Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("identity pool created")

	// set roles for identity pool
	roleMappings := make(map[string]identity.RoleMapping, 1)
	role := identity.RoleMapping{
		AmbiguousRoleResolution: identity.AmbiguousRoleResolutionTypeDeny,
		Type:                    identity.RoleMappingTypeToken,
	}

	roleMapKey := fmt.Sprintf("cognito-idp.%s.amazonaws.com/%s:%s", p.region, orgData.UserPoolID, orgData.UserPoolAppClientID)
	roleMappings[roleMapKey] = role

	identityRoles := make(map[string]string, 2)
	identityRoles["authenticated"] = roles["authenticated"]
	identityRoles["unauthenticated"] = roles["unauthenticated"]

	input := &identity.SetIdentityPoolRolesInput{
		IdentityPoolId: out.IdentityPoolId,
		RoleMappings:   roleMappings,
		Roles:          identityRoles,
	}

	setRolesReq := p.fedSvc.SetIdentityPoolRolesRequest(input)

	_, err = setRolesReq.Send()
	if err != nil {
		identityErr := checkError("set_identity_roles", err)
		return "", identityErr
	}
	log.Info().Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("identity pool roles set")

	return *out.IdentityPoolId, nil
}

func (p *OrgProvisioner) createOwnerUser(ctx context.Context, orgData *am.Organization, password string) error {
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
			cip.AttributeType{
				Name:  aws.String("email_verified"),
				Value: aws.String("True"),
			},
		},
		UserPoolId: aws.String(orgData.UserPoolID),
		Username:   aws.String(orgData.OwnerEmail),
	}

	if password != "" {
		user.TemporaryPassword = aws.String(password)
		user.MessageAction = cip.MessageActionTypeSuppress
	}

	req := p.svc.AdminCreateUserRequest(user)
	out, err := req.Send()
	if err != nil {
		return checkError("create_owner_user", err)
	}

	// add owner user to owner group
	group := &cip.AdminAddUserToGroupInput{
		GroupName:  aws.String("owner"),
		UserPoolId: aws.String(orgData.UserPoolID),
		Username:   out.User.Username,
	}

	groupReq := p.svc.AdminAddUserToGroupRequest(group)
	_, err = groupReq.Send()
	if err != nil {
		return checkError("add_owner_to_group", err)
	}
	return err
}

func (p *OrgProvisioner) DeleteSupportOrganization(ctx context.Context, userContext am.UserContext, orgName string) (string, string, error) {
	_, org, err := p.orgClient.Get(ctx, userContext, orgName)
	if err != nil {
		return "unknownuserpool:1", "unknownidentitypool:1", err
	}

	if org == nil {
		return "unknownuserpool:1", "unknownidentitypool:1", errors.New("unable to get organization from org client")
	}

	if org.IdentityPoolID == "" || org.UserPoolID == "" {
		return "unknownuserpool:1", "unknownidentitypool:1", errors.New("org did not have pool ids set, probably failed create")
	}

	err = p.Delete(ctx, org)
	return org.UserPoolID, org.IdentityPoolID, err
}

// cleanUp similar to delete, but just print errors
func (p *OrgProvisioner) cleanUp(ctx context.Context, orgData *am.Organization) {
	if deleteErr := p.deleteIdentityPool(ctx, orgData); deleteErr != nil {
		log.Error().Err(deleteErr).Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("failed to delete identity pool")
	}
	if deleteErr := p.deleteUserPool(ctx, orgData); deleteErr != nil {
		log.Error().Err(deleteErr).Str("orgname", orgData.OrgName).Str("user_pool_id", orgData.UserPoolID).Msg("failed to delete user pool")
	}
}

// Delete the identity pool and user
func (p *OrgProvisioner) Delete(ctx context.Context, orgData *am.Organization) error {

	if deleteErr := p.deleteIdentityPool(ctx, orgData); deleteErr != nil {
		return deleteErr
	}

	if deleteErr := p.deleteUserPool(ctx, orgData); deleteErr != nil {
		return deleteErr
	}
	return nil
}

func (p *OrgProvisioner) deleteUserPool(ctx context.Context, orgData *am.Organization) error {
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

func (p *OrgProvisioner) deleteIdentityPool(ctx context.Context, orgData *am.Organization) error {
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

func (p *OrgProvisioner) List() (map[string]*am.Organization, error) {
	return nil, nil
}

func checkError(action string, err error) error {
	if awsErr, ok := err.(awserr.Error); ok {
		// Get error details
		log.Error().Err(awsErr).Str("aws_code", awsErr.Code()).Str("aws_message", awsErr.Message()).Str("action", action).Msg("aws error")
		return awsErr
	}
	return err
}
