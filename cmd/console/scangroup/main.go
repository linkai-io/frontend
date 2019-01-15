package main

import (
	"os"
	"time"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/frontend/api/console/scangroup"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var scanGroupClient am.ScanGroupService
var scanGroupEnv *scangroup.ScanGroupEnv
var env string
var region string

func init() {
	zerolog.TimeFieldFormat = ""
	scanGroupEnv := &scangroup.ScanGroupEnv{}

	log.Logger = log.With().Str("lambda", "ScanGroup").Logger()
	scanGroupEnv.Env = os.Getenv("APP_ENV")
	scanGroupEnv.Region = os.Getenv("APP_REGION")
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	scanGroupClient = initializers.ScanGroupClient()
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	scanGroupHandlers := scangroup.New(scanGroupClient, scanGroupEnv)

	r.Route("/scangroup", func(r chi.Router) {
		r.Get("/groups", scanGroupHandlers.GetScanGroups)
		r.Get("/id/{id}", scanGroupHandlers.GetScanGroupByID)
		r.Post("/name/{name}", scanGroupHandlers.CreateScanGroup)
		r.Patch("/id/{id}", scanGroupHandlers.UpdateScanGroup)
		r.Delete("/id/{id}", scanGroupHandlers.DeleteScanGroup)
		r.Patch("/id/{id}/status", scanGroupHandlers.UpdateScanGroupStatus)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
