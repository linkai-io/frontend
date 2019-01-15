package admin_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/api/console/admin"
	"github.com/linkai-io/frontend/fetest"
)

func TestHealth(t *testing.T) {
	if os.Getenv("INFRA_TESTS") == "" {
		t.Skip()
	}
	health := admin.NewHealthHandlers()
	r := chi.NewRouter()
	r.Get("/admin/health", health.CheckHealth)

	ts := httptest.NewServer(r)
	defer ts.Close()

	rr, _ := fetest.RouterTestRequest(t, ts, "GET", "/admin/health", nil)

	// Check the status code is what we expect.
	if status := rr.StatusCode; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

}
