package main

import (
	"os"
	"time"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/clients/webdata"
	"github.com/linkai-io/am/pkg/lb/consul"
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

	r.Route("/web", func(r chi.Router) {
		r.Get("/responses", nil)
		r.Get("/certificates", nil)
		r.Get("/snapshots", nil)

	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
