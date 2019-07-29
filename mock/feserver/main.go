package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stripe/stripe-go/client"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/api/console/address"
	"github.com/linkai-io/frontend/api/console/event"
	"github.com/linkai-io/frontend/api/console/org"
	"github.com/linkai-io/frontend/api/console/scangroup"
	"github.com/linkai-io/frontend/api/console/user"
	"github.com/linkai-io/frontend/api/console/webdata"
	"github.com/linkai-io/frontend/mock/femock"
	"github.com/linkai-io/frontend/pkg/authz/awsauthz"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/token/awstoken"
)

func main() {
	env := "local"
	region := "us-east-1"
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("service", "FakeServer").Logger()

	secret := secrets.NewSecretsCache(env, region)
	stripeKey, err := secret.GetSecureString(fmt.Sprintf("/am/%s/billing/stripe/key", env))
	if err != nil {
		log.Fatal().Err(err).Msg("error reading stripe key")
	}

	sc := &client.API{}
	sc.Init(stripeKey, nil)

	r := chi.NewRouter()
	orgClient := femock.MockOrgClient()
	addrClient := femock.MockAddrClient()
	userClient := femock.MockUserClient()
	scanGroupClient := femock.MockScanGroupClient()
	webClient := femock.MockWebClient()
	eventClient := femock.MockEventClient()

	tokener := awstoken.New(env, region)
	authenticator := awsauthz.New(env, region, tokener)

	addrHandlers := address.New(addrClient, scanGroupClient, orgClient)
	addrHandlers.ContextExtractor = fakeContext

	orgHandlers := org.New(orgClient, sc)
	orgHandlers.ContextExtractor = fakeContext

	userHandlers := user.New(userClient, tokener, authenticator, orgClient, &user.UserEnv{Env: env, Region: region})
	userHandlers.ContextExtractor = fakeContext

	webHandlers := webdata.New(webClient)
	webHandlers.ContextExtractor = fakeContext

	scanGroupHandlers := scangroup.New(scanGroupClient, userClient, orgClient, &scangroup.ScanGroupEnv{Env: env, Region: region})
	scanGroupHandlers.ContextExtractor = fakeContext
	r.NotFound(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(404)
		fmt.Fprintf(w, "%#v not found", req.URL)
	}))

	eventHandlers := event.New(eventClient)
	eventHandlers.ContextExtractor = fakeContext

	testAuthHandler := &femock.TestAuth{}
	// auth
	r.Route("/auth", func(r chi.Router) {
		r.Get("/health", middleware.Health)
		r.Post("/refresh", testAuthHandler.Refresh)
		r.Post("/login", testAuthHandler.Login)
		r.Post("/forgot", testAuthHandler.Forgot)
		r.Post("/forgot_confirm", testAuthHandler.ForgotConfirm)
		r.Post("/changepwd", testAuthHandler.ChangePwd)
	})

	// for addresses
	r.Route("/address", func(r chi.Router) {
		r.Get("/stats", addrHandlers.OrgStats)
		r.Get("/group/{id}", addrHandlers.GetAddresses)
		r.Get("/group/{id}/hosts", addrHandlers.GetHostList)
		r.Get("/group/{id}/hosts/download", addrHandlers.ExportHostList)
		r.Get("/group/{id}/ports", addrHandlers.GetPorts)
		r.Get("/group/{id}/ports/download", addrHandlers.ExportPorts)
		r.Put("/group/{id}/add", addrHandlers.PutAddresses)
		r.Get("/group/{id}/count", addrHandlers.GetGroupCount)
		r.Post("/group/{id}/download", addrHandlers.ExportAddresses)
		r.Patch("/group/{id}/delete", addrHandlers.DeleteAddresses)
		r.Patch("/group/{id}/ignore", addrHandlers.IgnoreAddresses)
	})

	// testing scangroups
	r.Route("/scangroup", func(r chi.Router) {
		r.Get("/groups", scanGroupHandlers.GetScanGroups)
		r.Get("/groups/stats", scanGroupHandlers.GetGroupStats)
		r.Get("/name/{name}", scanGroupHandlers.GetScanGroupByName)
		r.Post("/name/{name}", scanGroupHandlers.CreateScanGroup)
		r.Patch("/name/{name}", scanGroupHandlers.UpdateScanGroup)
		r.Delete("/name/{name}", scanGroupHandlers.DeleteScanGroup)
		r.Patch("/name/{name}/status", scanGroupHandlers.UpdateScanGroupStatus)
	})

	// testing org
	r.Route("/org", func(r chi.Router) {
		r.Get("/name/{name}", orgHandlers.GetByName)
		r.Get("/id/{id}", orgHandlers.GetByID)
		r.Patch("/id/{id}", orgHandlers.Update)
		r.Delete("/id/{id}", orgHandlers.Delete)
		r.Get("/cid/{cid}", orgHandlers.GetByCID)
		r.Get("/list", orgHandlers.List)
		r.Get("/billing", orgHandlers.GetBilling)
	})

	// testing user
	r.Route("/user", func(r chi.Router) {
		r.Get("/details", userHandlers.Get)
		r.Patch("/accept", userHandlers.AcceptAgreement)
		r.Post("/feedback", userHandlers.SubmitFeedback)
		r.Patch("/details", userHandlers.UpdateUser)
		r.Patch("/password", userHandlers.ChangePassword)
	})

	// webdata
	r.Route("/webdata", func(r chi.Router) {
		r.Get("/stats", webHandlers.OrgStats)
		r.Get("/group/{id}/snapshots", webHandlers.GetSnapshots)
		r.Get("/group/{id}/snapshots/download", webHandlers.ExportSnapshots)
		r.Get("/group/{id}/certificates", webHandlers.GetCertificates)
		r.Post("/group/{id}/certificates/download", webHandlers.ExportCertificates)
		r.Get("/group/{id}/responses", webHandlers.GetResponses)
		r.Post("/group/{id}/responses/download", webHandlers.ExportResponses)
		r.Get("/group/{id}/urls", webHandlers.GetURLList)
		r.Get("/group/{id}/techdata", webHandlers.GetTechData)
		r.Get("/group/{id}/domains", webHandlers.GetDomainDependencies)
	})

	// events
	r.Route("/event", func(r chi.Router) {
		r.Get("/group/{id}/events", eventHandlers.Get)
		r.Patch("/group/{id}/events", eventHandlers.MarkRead)
		r.Get("/settings", eventHandlers.GetSettings)
		r.Patch("/settings", eventHandlers.UpdateSettings)
	})

	billingHandlers := femock.MockWebHooks(env, region, sc, orgClient, secret)
	r.Route("/incoming", func(r chi.Router) {
		r.Post("/stripe_events", billingHandlers.HandleStripe)
	})

	log.Info().Msg("listening on :3000")
	err = http.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}

func fakeContext(ctx context.Context) (am.UserContext, bool) {
	return &am.UserContextData{OrgID: 1, UserID: 1, UserCID: "test@test.com", OrgCID: "somerandomvalue", SubscriptionID: 103}, true
}
