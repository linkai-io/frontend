package femock

import (
	"fmt"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/api/incoming/billing"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog/log"
	"github.com/stripe/stripe-go/client"
)

func MockWebHooks(env, region string, sc *client.API, orgClient am.OrganizationService, secret *secrets.SecretsCache) *billing.BillingHandlers {

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

	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	return billing.New(orgClient, systemContext, sc, endpointKey)
}
