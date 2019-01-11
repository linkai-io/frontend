package health_test

import (
	"context"
	"os"
	"testing"

	"github.com/linkai-io/frontend/pkg/health"
)

func TestQueryServices(t *testing.T) {
	if os.Getenv("INFRA_TESTS") == "" {
		t.Skip("skipping infrastructure tests")
	}
	h := health.New()
	if err := h.Init(); err != nil {
		t.Fatalf("error init %v\n", err)
	}
	ctx := context.Background()

	services, err := h.QueryServices(ctx)
	if err != nil {
		t.Fatalf("error querying services: %v\n", err)
	}

	h.CheckGRPCServices(ctx, services)
	for addr, service := range services {
		t.Logf("%s %#v\n", addr, service)
	}
}
