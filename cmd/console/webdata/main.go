package main

import (
	"os"
	"time"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/clients/webdata"
	"github.com/linkai-io/am/pkg/lb/consul"
	wd "github.com/linkai-io/frontend/api/console/webdata"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
)

var webClient am.WebDataService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Address").Logger()
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata
	webClient = webdata.New()
	if err := webClient.Init(nil); err != nil {
		log.Fatal().Err(err).Msg("error initializing webdata client")
	}
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)

	webHandlers := wd.New(webClient)
	r.Route("/webdata", func(r chi.Router) {
		r.Get("/group/{id}/snapshots", webHandlers.GetSnapshots)
		r.Post("/group/{id}/snapshots/download", webHandlers.ExportSnapshots)
		r.Get("/group/{id}/certificates", webHandlers.GetCertificates)
		r.Post("/group/{id}/certificates/download", webHandlers.ExportCertificates)
		r.Get("/group/{id}/responses", webHandlers.GetResponses)
		r.Post("/group/{id}/responses/download", webHandlers.ExportResponses)
		r.Get("/group/{id}/urls", webHandlers.GetURLList)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
