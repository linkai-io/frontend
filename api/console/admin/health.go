package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/linkai-io/frontend/pkg/health"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog/log"
)

type HealthData struct {
	Status   string                           `json:"status"`
	Services map[string]*health.ServiceHealth `json:"service_health"`
}

type HealthHandlers struct {
	ContextExtractor middleware.UserContextExtractor
	healthChecker    *health.HealthChecker
}

func NewHealthHandlers() *HealthHandlers {
	return &HealthHandlers{
		ContextExtractor: middleware.ExtractUserContext,
		healthChecker:    health.New(),
	}
}

func (h *HealthHandlers) CheckHealth(w http.ResponseWriter, req *http.Request) {
	var data []byte

	log.Info().Msg("check health called")

	adminContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	if adminContext.GetSubscriptionID() != 9999 {
		middleware.ReturnError(w, "invalid user access attempt", 401)
		return
	}

	if err := h.healthChecker.Init(); err != nil {
		middleware.ReturnError(w, err.Error(), 401)
		return
	}

	services, err := h.healthChecker.QueryServices(req.Context())
	if err != nil {
		middleware.ReturnError(w, err.Error(), 401)
		return
	}
	h.healthChecker.CheckGRPCServices(req.Context(), services)

	resp := &HealthData{Status: "ok", Services: services}
	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}
