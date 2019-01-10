package main

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

func CheckHealth(w http.ResponseWriter, req *http.Request) {
	var data []byte

	log.Info().Msg("check health called")

	_, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	h := health.New()
	if err := h.Init(); err != nil {
		middleware.ReturnError(w, err.Error(), 401)
		return
	}
	services, err := h.QueryServices(req.Context())
	if err != nil {
		middleware.ReturnError(w, err.Error(), 401)
		return
	}
	h.CheckGRPCServices(req.Context(), services)

	resp := &HealthData{Status: "ok", Services: services}
	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}
