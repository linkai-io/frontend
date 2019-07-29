package femock

import (
	"context"
	"sync"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
)

func MockOrgClient() am.OrganizationService {
	orgClient := &mock.OrganizationService{}
	orgs := make(map[string]*am.Organization)
	orgLock := &sync.RWMutex{}

	orgClient.GetFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		org = BuildOrg(userContext, orgName, userContext.GetOrgID())
		return userContext.GetOrgID(), org, nil
	}
	orgClient.GetByIDFn = func(ctx context.Context, userContext am.UserContext, orgID int) (oid int, org *am.Organization, err error) {
		org = BuildOrg(userContext, "test", userContext.GetOrgID())
		return userContext.GetOrgID(), org, nil
	}

	orgClient.GetByCIDFn = func(ctx context.Context, userContext am.UserContext, orgCID string) (oid int, org *am.Organization, err error) {
		orgLock.Lock()
		defer orgLock.Unlock()

		if org, ok := orgs[orgCID]; ok {
			return org.OrgID, org, nil
		}

		org = BuildOrg(userContext, orgCID, userContext.GetOrgID())
		return userContext.GetOrgID(), org, nil
	}

	orgClient.UpdateFn = func(ctx context.Context, userContext am.UserContext, updated *am.Organization) (oid int, err error) {
		orgLock.Lock()
		defer orgLock.Unlock()
		orgs[updated.OrgCID] = updated
		return userContext.GetOrgID(), nil
	}
	return orgClient
}

func BuildOrg(userContext am.UserContext, orgName string, orgID int) *am.Organization {
	return &am.Organization{
		OrgID:                      userContext.GetOrgID(),
		OrgCID:                     "test",
		OrgName:                    orgName,
		OwnerEmail:                 "test@" + orgName + ".com",
		UserPoolID:                 "test",
		UserPoolAppClientID:        "test",
		UserPoolAppClientSecret:    "test",
		IdentityPoolID:             "test",
		UserPoolJWK:                "test",
		FirstName:                  "test",
		LastName:                   "test",
		Phone:                      "test",
		Country:                    "test",
		StatePrefecture:            "test",
		Street:                     "test",
		Address1:                   "test",
		Address2:                   "test",
		City:                       "test",
		PostalCode:                 "test",
		CreationTime:               time.Now().UnixNano(),
		StatusID:                   am.OrgStatusActive,
		Deleted:                    false,
		SubscriptionID:             am.SubscriptionEnterprise,
		LimitTLD:                   3,
		LimitTLDReached:            false,
		LimitHosts:                 10000,
		LimitHostsReached:          false,
		LimitCustomWebFlows:        0,
		LimitCustomWebFlowsReached: false,
		PortScanEnabled:            true,
		PaymentRequiredTimestamp:   time.Now().Add(time.Hour * 24 * 14).UnixNano(),
		BillingPlanType:            "",
		BillingPlanID:              "",
		BillingSubscriptionID:      "",
		IsBetaPlan:                 true,
	}
}
