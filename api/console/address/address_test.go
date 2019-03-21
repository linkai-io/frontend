package address_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/frontend/api/console/address"
	"github.com/linkai-io/frontend/fetest"
)

func TestGetAddresses(t *testing.T) {
	orgClient := &mock.OrganizationService{}
	orgClient.GetByCIDFn = mockGetOrgByCIDfunc

	addrClient := &mock.AddressService{}
	addrClient.GetFn = func(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (int, []*am.ScanGroupAddress, error) {
		addresses := make([]*am.ScanGroupAddress, 1)
		addresses[0] = &am.ScanGroupAddress{
			AddressID:           1,
			OrgID:               userContext.GetOrgID(),
			GroupID:             filter.GroupID,
			HostAddress:         "example.com",
			IPAddress:           "1.1.1.1",
			DiscoveryTime:       0,
			DiscoveredBy:        "",
			LastScannedTime:     0,
			LastSeenTime:        0,
			ConfidenceScore:     0.0,
			UserConfidenceScore: 0.0,
			IsSOA:               false,
			IsWildcardZone:      false,
			IsHostedService:     false,
			Ignored:             false,
			FoundFrom:           "",
			NSRecord:            0,
			AddressHash:         "somehash",
		}
		return userContext.GetOrgID(), addresses, nil
	}
	addrClient.CountFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		return userContext.GetOrgID(), 1, nil
	}

	scanGroupClient := &mock.ScanGroupService{}
	addr := address.New(addrClient, scanGroupClient, orgClient)
	addr.ContextExtractor = func(ctx context.Context) (am.UserContext, bool) {
		return &am.UserContextData{UserID: 1, OrgID: 1}, true
	}

	r := chi.NewRouter()
	r.Route("/address", func(r chi.Router) {
		r.Get("/group/{id}", addr.GetAddresses)
		r.Put("/group/{id}/initial", addr.PutInitialAddresses)
		r.Get("/group/{id}/count", addr.GetGroupCount)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	rr, body := fetest.RouterTestRequest(t, ts, "GET", "/address/group/1", nil)

	// Check the status code is what we expect.
	if status := rr.StatusCode; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	resp := &address.AddressResponse{}
	if err := json.Unmarshal([]byte(body), resp); err != nil {
		t.Fatalf("error getting addr data: %s\n", err)
	}

	if resp.LastIndex != 1 {
		t.Fatalf("last index expected %v got %v\n", 1, resp.LastIndex)
	}
}

func TestPutInitialAddresses(t *testing.T) {
	orgClient := &mock.OrganizationService{}
	orgClient.GetByCIDFn = mockGetOrgByCIDfunc

	addrClient := &mock.AddressService{}
	addrClient.GetFn = func(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (int, []*am.ScanGroupAddress, error) {
		addresses := make([]*am.ScanGroupAddress, 1)
		addresses[0] = &am.ScanGroupAddress{
			AddressID:           1,
			OrgID:               userContext.GetOrgID(),
			GroupID:             filter.GroupID,
			HostAddress:         "example.com",
			IPAddress:           "1.1.1.1",
			DiscoveryTime:       0,
			DiscoveredBy:        "",
			LastScannedTime:     0,
			LastSeenTime:        0,
			ConfidenceScore:     0.0,
			UserConfidenceScore: 0.0,
			IsSOA:               false,
			IsWildcardZone:      false,
			IsHostedService:     false,
			Ignored:             false,
			FoundFrom:           "",
			NSRecord:            0,
			AddressHash:         "somehash",
		}
		return userContext.GetOrgID(), addresses, nil
	}
	addrClient.CountFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		return userContext.GetOrgID(), 1, nil
	}

	addrClient.UpdateFn = func(ctx context.Context, userContext am.UserContext, addresses map[string]*am.ScanGroupAddress) (oid int, count int, err error) {
		return userContext.GetOrgID(), len(addresses), nil
	}

	scanGroupClient := &mock.ScanGroupService{}
	addr := address.New(addrClient, scanGroupClient, orgClient)
	addr.ContextExtractor = func(ctx context.Context) (am.UserContext, bool) {
		return &am.UserContextData{UserID: 1, OrgID: 1}, true
	}

	r := chi.NewRouter()
	r.Route("/address", func(r chi.Router) {
		r.Get("/group/{id}", addr.GetAddresses)
		r.Put("/group/{id}/initial", addr.PutInitialAddresses)
		r.Get("/group/{id}/count", addr.GetGroupCount)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	type tt struct {
		Input  string
		Error  bool
		Code   int
		Status string
	}

	hosts := make([]string, 26)
	for i := 0; i < 26; i++ {
		hosts[i] = fmt.Sprintf("%d.linkai.io", i)
	}
	hostsString := strings.Join(hosts, "\n")

	tests := []tt{
		{
			Input:  "linkai.io",
			Error:  false,
			Code:   200,
			Status: "OK",
		},
		{
			Input:  "linkai.io\ntest.linkai.io",
			Error:  false,
			Code:   200,
			Status: "OK",
		},
		{
			Input:  "linkai.io\ntest.example.io",
			Error:  true,
			Code:   400,
			Status: "error",
		},
		{
			Input:  hostsString,
			Error:  true,
			Code:   400,
			Status: "error",
		},
	}

	for _, test := range tests {
		b := strings.NewReader(test.Input)
		rr, body := fetest.RouterTestRequest(t, ts, "PUT", "/address/group/1/initial", b)

		// Check the status code is what we expect.
		if status := rr.StatusCode; status != test.Code {
			t.Fatalf("handler returned wrong status code: got %v want %v", status, test.Code)
		}
		t.Logf("%s\n", string(body))
		resp := &address.PutResponse{}
		if err := json.Unmarshal([]byte(body), resp); err != nil {
			t.Fatalf("error getting addr data: %s\n", err)
		}

		if resp.Status != test.Status {
			t.Logf("%#v\n", resp)
			t.Fatalf("expected %v response: %v\n", test.Status, resp.Status)
		}
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
