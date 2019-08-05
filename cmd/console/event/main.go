package main

import (
	"os"
	"time"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/frontend/api/console/event"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/wirepair/gateway"
)

var eventClient am.EventService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Event").Logger()

	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	eventClient = initializers.EventClient()

}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	eventHandlers := event.New(eventClient)

	r.Route("/event", func(r chi.Router) {
		r.Get("/group/{id}/events", eventHandlers.Get)
		r.Patch("/group/{id}/events", eventHandlers.MarkRead)
		r.Get("/settings", eventHandlers.GetSettings)
		r.Patch("/settings", eventHandlers.UpdateSettings)
		r.Post("/test_webhook", eventHandlers.SendTestWebhookEvent)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
