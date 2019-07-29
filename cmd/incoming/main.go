package main

import (
	"fmt"
	"os"
	"time"

	"github.com/linkai-io/frontend/api/incoming/billing"
	"github.com/linkai-io/frontend/pkg/initializers"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/wirepair/gateway"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/stripe/stripe-go/client"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/am/pkg/secrets"
)

var secret *secrets.SecretsCache
var orgClient am.OrganizationService
var env string
var region string

func init() {
	zerolog.TimeFieldFormat = ""
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	log.Logger = log.With().Str("lambda", "Org").Logger()
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata
	secret = secrets.NewSecretsCache(env, region)
	orgClient = initializers.OrgClient()
}

func main() {
	stripeKey, err := secret.GetSecureString(fmt.Sprintf("/am/%s/billing/stripe/key", env))
	if err != nil {
		log.Fatal().Err(err).Msg("error reading stripe key")
	}

	endpointKey, err := secret.GetSecureString(fmt.Sprintf("/am/%s/billing/stripe/endpoint_key", env))
	if err != nil {
		log.Fatal().Err(err).Msg("error reading webhook endpoint key")
	}

	systemOrgID, err := secret.SystemOrgID()
	if err != nil {
		log.Fatal().Err(err).Msg("error extracting system org id")
	}

	systemUserID, err := secret.SystemUserID()
	if err != nil {
		log.Fatal().Err(err).Msg("error extracting system user id")
	}

	systemContext := &am.UserContextData{
		TraceID:        "",
		OrgID:          systemOrgID,
		OrgCID:         "",
		UserID:         systemUserID,
		UserCID:        "",
		Roles:          []string{"owner"},
		IPAddress:      "",
		SubscriptionID: 9999,
		OrgStatusID:    9999,
	}

	sc := &client.API{}
	sc.Init(stripeKey, nil)

	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	billingHandlers := billing.New(orgClient, systemContext, sc, endpointKey)

	r.Route("/incoming", func(r chi.Router) {
		r.Post("/stripe_events", billingHandlers.HandleStripe)
	})

	err = gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
