package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/linkai-io/am/am"

	"github.com/linkai-io/frontend/pkg/provision"

	"github.com/linkai-io/am/mock"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/api/console/admin"
	"github.com/linkai-io/frontend/fetest"
	femock "github.com/linkai-io/frontend/mock"
)

func TestProvisionHandlersOrgPOST(t *testing.T) {
	orgClient := &mock.OrganizationService{}
	provisioner := &femock.OrgProvisioner{}
	provisioner.AddFn = func(ctx context.Context, userContext am.UserContext, orgData *am.Organization, roles map[string]string) (string, error) {
		return "userid", nil
	}

	roles := make(map[string]string, 0)
	provHandlers := admin.NewProvisionHandlers(orgClient, provisioner, roles)
	provHandlers.ContextExtractor = func(ctx context.Context) (am.UserContext, bool) {
		return &am.UserContextData{
			UserID: 1,
			OrgID:  1,
		}, true
	}
	r := chi.NewRouter()
	r.Route("/admin", func(admin chi.Router) {
		admin.Route("/provision", func(prov chi.Router) {
			prov.Post("/org/{name}", provHandlers.CreateOrg)
			prov.Delete("/org/{name}", provHandlers.DeleteOrg)
			prov.Patch("/org/{name}", provHandlers.UpdateOrg)
			prov.Post("/user/{name}", provHandlers.CreateUser)
		})
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	orgDetails := &provision.OrgDetails{
		OrgName:         "test",
		OwnerEmail:      "test@test.com",
		FirstName:       "test",
		LastName:        "test",
		Phone:           "1-111-1111-1111",
		Country:         "usa",
		StatePrefecture: "test",
		Street:          "test",
		Address1:        "test",
		Address2:        "test",
		City:            "test",
		PostalCode:      "test",
		StatusID:        am.OrgStatusActive,
		SubscriptionID:  am.SubscriptionMonthly,
	}
	data, err := json.Marshal(orgDetails)
	if err != nil {
		t.Fatalf("wat.")
	}

	rr, _ := fetest.RouterTestRequest(t, ts, "POST", "/admin/provision/org/test", bytes.NewReader(data))

	// Check the status code is what we expect.
	if status := rr.StatusCode; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if !provisioner.AddInvoked {
		t.Fatalf("add was not invoked")
	}
}

func TestProvisionHandlersAgainstAWS(t *testing.T) {
	if os.Getenv("INFRA_TESTS") == "" {
		t.Skip()
	}
}
