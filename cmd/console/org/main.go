package main

import (
	"os"
	"time"

	"github.com/linkai-io/frontend/api/console/org"
	"github.com/linkai-io/frontend/pkg/initializers"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
)

var orgClient am.OrganizationService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Org").Logger()
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	orgClient = initializers.OrgClient()
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	orgHandlers := org.New(orgClient)

	r.Route("/org", func(r chi.Router) {
		r.Get("/name/{name}", orgHandlers.GetByName)
		r.Get("/id/{id}", orgHandlers.GetByID)
		r.Patch("/id/{id}", orgHandlers.Update)
		r.Delete("/id/{id}", orgHandlers.Delete)
		r.Get("/cid/{cid}", orgHandlers.GetByCID)
		r.Get("/list", orgHandlers.List)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
