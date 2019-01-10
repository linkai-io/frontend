package health

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/hashicorp/consul/api"
	"github.com/rs/zerolog/log"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type HealthChecker struct {
	cfg    *api.Config
	client *api.Client
}

type ServiceHealth struct {
	Name   string `json:"service"`
	Addr   string `json:"address"`
	Status string `json:"status"`
}

func New() *HealthChecker {
	return &HealthChecker{cfg: api.DefaultConfig()}
}

func (h *HealthChecker) Init() error {
	var err error
	h.client, err = api.NewClient(h.cfg)
	if err != nil {
		return err
	}
	return nil
}

// QueryServices returns a list of services and their addresses for use in looking up their health
// via grpc health check
func (h *HealthChecker) QueryServices(ctx context.Context) (map[string]*ServiceHealth, error) {
	services, meta, err := h.client.Catalog().Services(nil)
	if err != nil {
		return nil, err
	}
	serviceMap := make(map[string]*ServiceHealth, 0)
	log.Info().Msgf("%v", meta)
	log.Info().Msgf("%#v", services)
	for k := range services {
		log.Info().Msgf("%s", k)
		if !strings.HasSuffix(k, "service") {
			continue
		}

		coor, _, err := h.client.Catalog().Service(k, "", nil)
		if err != nil {
			log.Error().Err(err).Str("service", k).Msg("failed to get service")
			continue
		}

		for _, s := range coor {
			addr := fmt.Sprintf("%s:%d", s.ServiceAddress, s.ServicePort)
			serviceMap[addr] = &ServiceHealth{Addr: addr, Name: k, Status: "UKNOWN"}
			log.Info().Msgf("%s %d", s.ServiceAddress, s.ServicePort)
		}
	}
	return serviceMap, nil
}

// CheckGRPCServices checks the health of each grpc service
func (h *HealthChecker) CheckGRPCServices(ctx context.Context, services map[string]*ServiceHealth) {
	for addr, service := range services {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()
		conn, err := grpc.DialContext(timeoutCtx, addr, grpc.WithInsecure())
		if err != nil {
			service.Status = err.Error()
			continue
		}
		resp, err := healthpb.NewHealthClient(conn).Check(timeoutCtx, &healthpb.HealthCheckRequest{Service: ""})
		if err != nil {
			service.Status = err.Error()
			continue
		}
		service.Status = resp.Status.String()
	}
	return
}
