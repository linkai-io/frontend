package health_test

import (
	"context"
	"testing"

	"github.com/linkai-io/frontend/pkg/health"
)

func TestQueryServices(t *testing.T) {
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
