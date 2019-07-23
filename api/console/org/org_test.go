package org_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/am/pkg/secrets"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/api/console/org"
	"github.com/linkai-io/frontend/fetest"
	"github.com/stripe/stripe-go/client"
)

func TestOrg(t *testing.T) {

}

func TestBilling(t *testing.T) {
	secret := secrets.NewSecretsCache("local", "")
	stripeKey, err := secret.GetSecureString(fmt.Sprintf("/am/%s/billing/stripe/key", "local"))
	if err != nil {
		t.Fatalf("error reading stripe key %v", err)
	}

	sc := &client.API{}
	sc.Init(stripeKey, nil)

	orgClient := &mock.OrganizationService{}
	orgClient.GetByCIDFn = mockGetOrgByCIDfunc
	orgHandlers := org.New(orgClient, sc)
	orgHandlers.ContextExtractor = func(ctx context.Context) (am.UserContext, bool) {
		return &am.UserContextData{UserID: 1, OrgID: 1, OrgCID: "abcd"}, true
	}

	r := chi.NewRouter()
	r.Route("/org", func(r chi.Router) {
		r.Get("/name/{name}", orgHandlers.GetByName)
		r.Get("/id/{id}", orgHandlers.GetByID)
		//r.Patch("/id/{id}", orgHandlers.Update)
		//r.Delete("/id/{id}", orgHandlers.Delete)
		r.Get("/cid/{cid}", orgHandlers.GetByCID)
		r.Get("/list", orgHandlers.List)
		r.Get("/billing", orgHandlers.GetBilling)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	rr, body := fetest.RouterTestRequest(t, ts, "GET", "/org/billing", nil)

	// Check the status code is what we expect.
	if status := rr.StatusCode; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	resp := &org.BillingResponse{}
	if err := json.Unmarshal([]byte(body), resp); err != nil {
		t.Fatalf("error getting addr data: %s\n", err)
	}

	if len(resp.Plans) != 3 {
		t.Fatalf("last index expected %v got %v\n", 3, len(resp.Plans))
	}
	for _, p := range resp.Plans {
		t.Logf("%#v %#v\n", p, p.Product)
	}
}

func mockGetOrgByCIDfunc(ctx context.Context, userContext am.UserContext, orgCID string) (int, *am.Organization, error) {
	return userContext.GetOrgID(), &am.Organization{
		OrgID:                      userContext.GetOrgID(),
		OrgCID:                     userContext.GetOrgCID(),
		OrgName:                    "test",
		OwnerEmail:                 "test@test.com",
		UserPoolID:                 "",
		UserPoolAppClientID:        "",
		UserPoolAppClientSecret:    "",
		IdentityPoolID:             "",
		UserPoolJWK:                "",
		FirstName:                  "",
		LastName:                   "",
		Phone:                      "",
		Country:                    "",
		StatePrefecture:            "",
		Street:                     "",
		Address1:                   "",
		Address2:                   "",
		City:                       "",
		PostalCode:                 "",
		CreationTime:               0,
		StatusID:                   0,
		Deleted:                    false,
		SubscriptionID:             101,
		LimitTLD:                   1,
		LimitTLDReached:            false,
		LimitHosts:                 25,
		LimitHostsReached:          false,
		LimitCustomWebFlows:        0,
		LimitCustomWebFlowsReached: false,
	}, nil
}
