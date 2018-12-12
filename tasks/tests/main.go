package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog/log"
)

var orgClient am.OrganizationService
var orgProvisioner *provision.OrgProvisioner
var env string
var region string

var systemOrgID int
var systemUserID int

func init() {

}

type responseData struct {
	UserPoolID     string `json:"UserPoolId,omitempty"`
	IdentityPoolID string `json:"IdentityPoolId,omitempty"`
}

func provisionResource(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	evtData, _ := json.Marshal(event)
	log.Info().Msgf("event data: %s", string(evtData))
	switch event.RequestType {
	case cfn.RequestCreate:
		physicalResourceID, data, err = create(ctx, event)
	case cfn.RequestUpdate:
		physicalResourceID, data, err = create(ctx, event)
	case cfn.RequestDelete:
		physicalResourceID, data, err = delete(ctx, event)
	}
	return physicalResourceID, data, err
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

	return "", data, err
}

func delete(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	data = make(map[string]interface{})
	log.Info().Msg("delete called")
	orgData := orgFromInput(event.ResourceProperties)
	physicalResourceID = env + "-" + region + "-" + orgData.OrgName
	event.PhysicalResourceID = physicalResourceID

	if orgData.OrgName == "" {
		log.Error().Msg("orgname is empty")
		return physicalResourceID, data, errors.New("error orgname is empty")
	}

	userContext := &am.UserContextData{
		OrgID:   systemOrgID,
		UserID:  systemUserID,
		TraceID: event.RequestID,
	}

	if err = orgProvisioner.DeleteSupportOrganization(ctx, userContext, orgData.OrgName); err != nil {
		log.Error().Err(err).Msg("failed to delete support org")
	}
	return physicalResourceID, data, err
}

func main() {
	out1, out2, err := provisionResource(nil, cfn.Event{})
	log.Printf("%v %v %v\n", out1, out2, err)
}
