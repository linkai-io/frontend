package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var orgClient am.OrganizationService
var orgProvisioner *provision.OrgProvisioner
var env string
var region string

var systemOrgID int
var systemUserID int

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Provisioner").Logger()
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	log.Info().Str("env", env).Str("region", region).Msg("provisioning initializing for stack")

	sec := secrets.NewSecretsCache(env, region)
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	if systemOrgID, err = sec.SystemOrgID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system org id")
	}

	if systemUserID, err = sec.SystemUserID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system user id")
	}

	log.Info().Int("org_id", systemOrgID).Int("user_id", systemUserID).Msg("provisioning with system ids")
	orgClient = organization.New()
	if err := orgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}

	log.Info().Str("load_balancer", lb).Msg("orgClient initialized with lb")
	orgProvisioner = provision.NewOrgProvisioner(env, region, orgClient)
}

type responseData struct {
	UserPoolID     string `json:"UserPoolId,omitempty"`
	IdentityPoolID string `json:"IdentityPoolId,omitempty"`
}

func provisionResource(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	evtData, _ := json.Marshal(event)
	log.Info().Msgf("event data: %s", string(evtData))
	log.Info().Msgf("cleanup: curl -H 'Content-Type:' -H 'Content-Length: 0' -X PUT \"%s\"", event.ResponseURL)
	switch event.RequestType {
	case cfn.RequestCreate:
		return create(ctx, event)
	case cfn.RequestUpdate:
		return create(ctx, event)
	case cfn.RequestDelete:
		return delete(ctx, event)
	}
	return
}

func orgFromInput(props map[string]interface{}) *am.Organization {
	orgName, _ := props["OrgName"].(string)
	supportEmail, _ := props["SupportEmail"].(string)
	firstName, _ := props["FirstName"].(string)
	lastName, _ := props["LastName"].(string)

	return &am.Organization{
		OrgName:    orgName,
		OwnerEmail: supportEmail,
		FirstName:  firstName,
		LastName:   lastName,
	}
}

func rolesFromInput(props map[string]interface{}) map[string]string {
	roles := make(map[string]string, 0)
	propRoles, _ := props["Roles"].(map[string]interface{})

	for k, v := range propRoles {
		switch ty := v.(type) {
		case map[string]interface{}:
			arn, _ := ty["Name"].(string)
			roles[k] = string(arn)
			log.Info().Str("role_name", k).Str("role_arn", roles[k]).Msg("role deserialized")
		case string:
			roles[k] = string(ty)
			log.Info().Str("role_name", k).Str("role_arn", roles[k]).Msg("role deserialized")
		}
	}

	return roles
}

func create(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	log.Info().Msg("create called")
	data = make(map[string]interface{})

	orgData := orgFromInput(event.ResourceProperties)
	physicalResourceID = env + "-" + region + "-" + orgData.OrgName
	roles := rolesFromInput(event.ResourceProperties)
	if len(roles) == 0 {
		return physicalResourceID, data, errors.New("roles was empty")
	}

	password, _ := event.ResourceProperties["Password"].(string)
	if password == "" {
		return physicalResourceID, data, errors.New("password was empty")
	}

	userContext := &am.UserContextData{
		OrgID:   systemOrgID,
		UserID:  systemUserID,
		TraceID: event.RequestID,
	}

	log.Info().Int("org_id", systemOrgID).Int("user_id", systemUserID).Str("org_name", orgData.OrgName).Msg("provisioning support organization")
	userPoolID, identityPoolID, err := orgProvisioner.AddSupportOrganization(ctx, userContext, orgData, roles, password)

	data["UserPoolId"] = userPoolID
	data["IdentityPoolId"] = identityPoolID
	log.Info().Str("UserPoolId", userPoolID).Str("IdentityPoolId", identityPoolID).Int("org_id", systemOrgID).Int("user_id", systemUserID).Str("org_name", orgData.OrgName).Msg("provisioning support organization complete")
	return physicalResourceID, data, err
}

func delete(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	data = make(map[string]interface{})
	log.Info().Msg("delete called")
	orgData := orgFromInput(event.ResourceProperties)
	physicalResourceID = env + "-" + region + "-" + orgData.OrgName

	if orgData.OrgName == "" {
		log.Error().Msg("orgname is empty")
		return physicalResourceID, data, errors.New("error orgname is empty")
	}

	userContext := &am.UserContextData{
		OrgID:   systemOrgID,
		UserID:  systemUserID,
		TraceID: event.RequestID,
	}

	userPoolID, identityPoolID, err := orgProvisioner.DeleteSupportOrganization(ctx, userContext, orgData.OrgName)
	if err != nil {
		log.Error().Err(err).Msg("failed to delete support org")
		return physicalResourceID, data, err
	}

	data["UserPoolId"] = userPoolID
	data["IdentityPoolId"] = identityPoolID

	return physicalResourceID, data, nil
}

func main() {
	fn := func(ctx context.Context, event cfn.Event) (reason string, err error) {
		r := cfn.NewResponse(&event)

		r.PhysicalResourceID, r.Data, err = provisionResource(ctx, event)
		if r.PhysicalResourceID == "" {
			r.PhysicalResourceID = lambdacontext.LogStreamName
		}

		if err != nil {
			r.Status = cfn.StatusFailed
			r.Reason = err.Error()
			log.Error().Err(err).Str("reason", r.Reason).Msg("sending status failed")
		} else {
			r.Status = cfn.StatusSuccess
		}

		err = r.Send()
		if err != nil {
			reason = err.Error()
			log.Error().Err(err).Str("reason", r.Reason).Msg("sending failed, falling back to failsafe")
			return "", failSafe(r, event)
		}
		return
	}
	lambda.Start(fn)
}

func failSafe(r *cfn.Response, event cfn.Event) error {
	client := http.DefaultClient
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, event.ResponseURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	log.Info().Str("url", event.ResponseURL).Str("body", string(body)).Msg("calling url")
	req.Header.Del("Content-Type")
	req.Header.Set("Content-Length", string(int64(len(body))))

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	res.Body.Close()

	if res.StatusCode != 200 {
		log.Error().Str("response_body", string(body)).Int("code", res.StatusCode).Msg("failed again wtf")
		return errors.New("invalid status code")
	}

	return nil
}
