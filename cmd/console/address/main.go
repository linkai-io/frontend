package main

import (
	"os"
	"time"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/frontend/api/console/address"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var addrClient am.AddressService
var scanGroupClient am.ScanGroupService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Address").Logger()

	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	scanGroupClient = initializers.ScanGroupClient()
	addrClient = initializers.AddressClient()
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	addr := address.New(addrClient, scanGroupClient)

	r.Route("/address", func(r chi.Router) {
		r.Get("/group/{id}", addr.GetAddresses)
		r.Put("/group/{id}/initial", addr.PutInitialAddresses)
		r.Get("/group/{id}/count", addr.GetGroupCount)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
