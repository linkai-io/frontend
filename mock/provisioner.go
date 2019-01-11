package mock

import (
	"context"

	"github.com/linkai-io/am/am"
)

type OrgProvisioner struct {
	AddSupportOrganizationFn      func(ctx context.Context, userContext am.UserContext, orgData *am.Organization, roles map[string]string, password string) (string, string, error)
	AddSupportOrganizationInvoked bool

	AddFn      func(ctx context.Context, userContext am.UserContext, orgData *am.Organization, roles map[string]string) (string, error)
	AddInvoked bool

	DeleteSupportOrganizationFn      func(ctx context.Context, userContext am.UserContext, orgName string) (string, string, error)
	DeleteSupportOrganizationInvoked bool

	DeleteFn      func(ctx context.Context, orgData *am.Organization) error
	DeleteInvoked bool
}

func (o *OrgProvisioner) AddSupportOrganization(ctx context.Context, userContext am.UserContext, orgData *am.Organization, roles map[string]string, password string) (string, string, error) {
	o.AddSupportOrganizationInvoked = true
	return o.AddSupportOrganizationFn(ctx, userContext, orgData, roles, password)
}

func (o *OrgProvisioner) Add(ctx context.Context, userContext am.UserContext, orgData *am.Organization, roles map[string]string) (string, error) {
	o.AddInvoked = true
	return o.AddFn(ctx, userContext, orgData, roles)
}

func (o *OrgProvisioner) DeleteSupportOrganization(ctx context.Context, userContext am.UserContext, orgName string) (string, string, error) {
	o.DeleteSupportOrganizationInvoked = true
	return o.DeleteSupportOrganization(ctx, userContext, orgName)
}

func (o *OrgProvisioner) Delete(ctx context.Context, orgData *am.Organization) error {
	o.DeleteInvoked = true
	return o.Delete(ctx, orgData)
}
