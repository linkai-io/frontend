package address_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/frontend/api/console/address"
	"github.com/linkai-io/frontend/fetest"
)

func TestGetAddresses(t *testing.T) {
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
	addr := address.New(addrClient, scanGroupClient)
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
