package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/frontend/api/console/address"
	"github.com/linkai-io/frontend/api/console/org"
	"github.com/linkai-io/frontend/api/console/scangroup"
	"github.com/linkai-io/frontend/api/console/user"
	"github.com/linkai-io/frontend/api/console/webdata"
	"github.com/linkai-io/frontend/pkg/authz/awsauthz"
	"github.com/linkai-io/frontend/pkg/token/awstoken"
)

func main() {
	env := "local"
	region := "us-east-1"
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("service", "FakeServer").Logger()

	r := chi.NewRouter()
	orgClient := testOrgClient()
	addrClient := testAddrClient()
	userClient := testUserClient()
	scanGroupClient := testScanGroupClient()
	webClient := testWebClient()

	tokener := awstoken.New(env, region)
	authenticator := awsauthz.New(env, region, tokener)

	addrHandlers := address.New(addrClient, scanGroupClient)
	addrHandlers.ContextExtractor = fakeContext

	orgHandlers := org.New(orgClient)
	orgHandlers.ContextExtractor = fakeContext

	userHandlers := user.New(userClient, tokener, authenticator, orgClient, &user.UserEnv{Env: env, Region: region})
	userHandlers.ContextExtractor = fakeContext

	webHandlers := webdata.New(webClient)
	webHandlers.ContextExtractor = fakeContext

	scanGroupHandlers := scangroup.New(scanGroupClient, &scangroup.ScanGroupEnv{Env: env, Region: region})
	scanGroupHandlers.ContextExtractor = fakeContext
	r.NotFound(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(404)
		fmt.Fprintf(w, "%#v not found", req.URL)
	}))
	// for addresses
	r.Route("/address", func(r chi.Router) {
		r.Get("/stats", addrHandlers.OrgStats)
		r.Get("/group/{id}", addrHandlers.GetAddresses)
		r.Get("/group/{id}/hosts", addrHandlers.GetHostList)
		r.Put("/group/{id}/initial", addrHandlers.PutInitialAddresses)
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
	})

	// testing user
	r.Route("/user", func(r chi.Router) {
		r.Post("/feedback", userHandlers.SubmitFeedback)
		r.Patch("/details", userHandlers.UpdateUser)
		r.Patch("/password", userHandlers.ChangePassword)
	})

	r.Route("/webdata", func(r chi.Router) {
		r.Get("/stats", webHandlers.OrgStats)
		r.Get("/group/{id}/snapshots", webHandlers.GetSnapshots)
		r.Post("/group/{id}/snapshots/download", webHandlers.ExportSnapshots)
		r.Get("/group/{id}/certificates", webHandlers.GetCertificates)
		r.Post("/group/{id}/certificates/download", webHandlers.ExportCertificates)
		r.Get("/group/{id}/responses", webHandlers.GetResponses)
		r.Post("/group/{id}/responses/download", webHandlers.ExportResponses)
		r.Get("/group/{id}/urls", webHandlers.GetURLList)
	})

	log.Info().Msg("listening on :3000")
	err := http.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}

func fakeContext(ctx context.Context) (am.UserContext, bool) {
	return &am.UserContextData{OrgID: 1, UserID: 1, UserCID: "test@test.com", OrgCID: "somerandomvalue"}, true
}

func testUserClient() am.UserService {
	userClient := &mock.UserService{}
	userClient.GetFn = func(ctx context.Context, userContext am.UserContext, userEmail string) (int, *am.User, error) {
		return userContext.GetOrgID(), &am.User{
			OrgID:        userContext.GetOrgID(),
			OrgCID:       "",
			UserCID:      "",
			UserID:       userContext.GetUserID(),
			UserEmail:    userEmail,
			FirstName:    "test",
			LastName:     "test",
			StatusID:     am.UserStatusActive,
			CreationTime: time.Now().UnixNano(),
			Deleted:      false,
		}, nil
	}
	return userClient
}

func testOrgClient() am.OrganizationService {
	orgClient := &mock.OrganizationService{}

	orgClient.GetFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		org = &am.Organization{
			OrgID:                   userContext.GetOrgID(),
			OrgCID:                  "test",
			OrgName:                 orgName,
			OwnerEmail:              "test@" + orgName + ".com",
			UserPoolID:              "test",
			UserPoolAppClientID:     "test",
			UserPoolAppClientSecret: "test",
			IdentityPoolID:          "test",
			UserPoolJWK:             "test",
			FirstName:               "test",
			LastName:                "test",
			Phone:                   "test",
			Country:                 "test",
			StatePrefecture:         "test",
			Street:                  "test",
			Address1:                "test",
			Address2:                "test",
			City:                    "test",
			PostalCode:              "test",
			CreationTime:            time.Now().UnixNano(),
			StatusID:                am.OrgStatusActive,
			Deleted:                 false,
			SubscriptionID:          am.SubscriptionMonthly,
		}
		return userContext.GetOrgID(), org, nil
	}
	return orgClient
}
