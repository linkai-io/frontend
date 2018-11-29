package main

import (
	"context"
	"testing"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/amtest"
	"github.com/linkai-io/am/mock"
)

func TestOrgProvision(t *testing.T) {
	userContext := amtest.CreateUserContext(1, 1)
	orgClient := &mock.OrganizationService{}
	orgClient.GetFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		return 0, nil, nil
	}

	provisioner := NewOrgProvisoner("dev", "us-east-1", orgClient)

	orgData := &am.Organization{
		OrgID:                   0,
		OrgCID:                  "",
		OrgName:                 "test-org",
		OwnerEmail:              "isaac.dawson@linkai.io",
		UserPoolID:              "",
		UserPoolAppClientID:     "",
		UserPoolAppClientSecret: "",
		IdentityPoolID:          "",
		FirstName:               "isaac",
		LastName:                "dawson",
		Phone:                   "placeholder",
		Country:                 "placeholder",
		StatePrefecture:         "placeholder",
		Street:                  "placeholder",
		Address1:                "placeholder",
		Address2:                "placeholder",
		City:                    "placeholder",
		PostalCode:              "placeholder",
		CreationTime:            0,
		StatusID:                0,
		Deleted:                 false,
		SubscriptionID:          am.SubscriptionMonthly,
	}
	ctx := context.Background()

	if err := provisioner.Add(ctx, userContext, orgData); err != nil {
		t.Fatalf("Error provisioning: %v\n", err)
	}
}
