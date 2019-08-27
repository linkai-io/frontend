package main

import (
	"os"
	"time"

	"github.com/linkai-io/am/pkg/webhooks"

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
var hooks webhooks.Webhooker

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Event").Logger()

	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	eventClient = initializers.EventClient()

	env := os.Getenv("APP_ENV")
	region := os.Getenv("APP_REGION")
	hooks = webhooks.New(env, region)
	if err := hooks.Init(); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize webhooks")
	}
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	eventHandlers := event.New(eventClient, hooks)

	r.Route("/event", func(r chi.Router) {
		r.Get("/group/{id}/events", eventHandlers.Get)
		r.Patch("/group/{id}/events", eventHandlers.MarkRead)
		r.Post("/group/{id}/webhooks", eventHandlers.UpdateWebhooks)
		r.Get("/settings", eventHandlers.GetSettings)
		r.Patch("/settings", eventHandlers.UpdateSettings)
		r.Post("/webhook_test", eventHandlers.SendTestWebhookEvent)
		r.Get("/webhook_events", eventHandlers.GetLastWebhookEvents)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
