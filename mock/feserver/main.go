package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/frontend/api/console/address"
	"github.com/linkai-io/frontend/api/console/event"
	"github.com/linkai-io/frontend/api/console/org"
	"github.com/linkai-io/frontend/api/console/scangroup"
	"github.com/linkai-io/frontend/api/console/user"
	"github.com/linkai-io/frontend/api/console/webdata"
	"github.com/linkai-io/frontend/pkg/authz/awsauthz"
	"github.com/linkai-io/frontend/pkg/middleware"
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
	eventClient := testEventClient()

	tokener := awstoken.New(env, region)
	authenticator := awsauthz.New(env, region, tokener)

	addrHandlers := address.New(addrClient, scanGroupClient, orgClient)
	addrHandlers.ContextExtractor = fakeContext

	orgHandlers := org.New(orgClient)
	orgHandlers.ContextExtractor = fakeContext

	userHandlers := user.New(userClient, tokener, authenticator, orgClient, &user.UserEnv{Env: env, Region: region})
	userHandlers.ContextExtractor = fakeContext

	webHandlers := webdata.New(webClient)
	webHandlers.ContextExtractor = fakeContext

	scanGroupHandlers := scangroup.New(scanGroupClient, userClient, &scangroup.ScanGroupEnv{Env: env, Region: region})
	scanGroupHandlers.ContextExtractor = fakeContext
	r.NotFound(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(404)
		fmt.Fprintf(w, "%#v not found", req.URL)
	}))

	eventHandlers := event.New(eventClient)
	eventHandlers.ContextExtractor = fakeContext

	testAuthHandler := &testAuth{}
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
		r.Post("/group/{id}/snapshots/download", webHandlers.ExportSnapshots)
		r.Get("/group/{id}/certificates", webHandlers.GetCertificates)
		r.Post("/group/{id}/certificates/download", webHandlers.ExportCertificates)
		r.Get("/group/{id}/responses", webHandlers.GetResponses)
		r.Post("/group/{id}/responses/download", webHandlers.ExportResponses)
		r.Get("/group/{id}/urls", webHandlers.GetURLList)
		r.Get("/group/{id}/techdata", webHandlers.GetTechData)
	})

	// events
	r.Route("/event", func(r chi.Router) {
		r.Get("/events", eventHandlers.Get)
		r.Patch("/events", eventHandlers.MarkRead)
		r.Get("/settings", eventHandlers.GetSettings)
		r.Patch("/settings", eventHandlers.UpdateSettings)
	})

	log.Info().Msg("listening on :3000")
	err := http.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}

func fakeContext(ctx context.Context) (am.UserContext, bool) {
	return &am.UserContextData{OrgID: 1, UserID: 1, UserCID: "test@test.com", OrgCID: "somerandomvalue", SubscriptionID: 1000}, true
}

func testUserClient() am.UserService {
	userClient := &mock.UserService{}
	user := &am.User{
		UserEmail:                  "test@test.com",
		FirstName:                  "test",
		LastName:                   "test",
		StatusID:                   am.UserStatusActive,
		CreationTime:               time.Now().UnixNano(),
		Deleted:                    false,
		AgreementAccepted:          false,
		AgreementAcceptedTimestamp: 0,
	}
	userClient.GetFn = func(ctx context.Context, userContext am.UserContext, userEmail string) (int, *am.User, error) {
		user.OrgID = userContext.GetOrgID()
		user.UserCID = userContext.GetUserCID()
		user.OrgCID = userContext.GetOrgCID()
		user.UserID = userContext.GetUserID()
		return userContext.GetOrgID(), user, nil
	}

	userClient.GetByCIDFn = userClient.GetFn

	userClient.AcceptAgreementFn = func(ctx context.Context, userContext am.UserContext, accepted bool) (int, int, error) {
		user.AgreementAccepted = accepted
		user.AgreementAcceptedTimestamp = time.Now().UnixNano()
		return userContext.GetOrgID(), userContext.GetUserID(), nil
	}

	return userClient
}

func testOrgClient() am.OrganizationService {
	orgClient := &mock.OrganizationService{}

	orgClient.GetFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		org = buildOrg(userContext, orgName, userContext.GetOrgID())
		return userContext.GetOrgID(), org, nil
	}
	orgClient.GetByIDFn = func(ctx context.Context, userContext am.UserContext, orgID int) (oid int, org *am.Organization, err error) {
		org = buildOrg(userContext, "test", userContext.GetOrgID())
		return userContext.GetOrgID(), org, nil
	}
	orgClient.GetByCIDFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		org = buildOrg(userContext, orgName, userContext.GetOrgID())
		return userContext.GetOrgID(), org, nil
	}
	return orgClient
}

func testEventClient() am.EventService {
	eventClient := &mock.EventService{}
	eventLock := &sync.RWMutex{}

	events := make(map[int64]*am.Event, 4)
	events[0] = &am.Event{
		NotificationID: 0,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventAXFR,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"ns1.example.com", "ns2.example.com"},
		Read:           false,
	}
	events[1] = &am.Event{
		NotificationID: 1,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewHost,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"www.example.com", "test.example.com"},
		Read:           false,
	}
	events[2] = &am.Event{
		NotificationID: 2,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewWebsite,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"https://example.com", "443", "http://www.example.com", "80"},
		Read:           false,
	}
	events[3] = &am.Event{
		NotificationID: 3,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventCertExpiring,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"example.com", "443", "24 hours"},
		Read:           false,
	}

	eventSettings := &am.UserEventSettings{
		WeeklyReportSendDay: 0,
		ShouldWeeklyEmail:   false,
		DailyReportSendHour: 0,
		ShouldDailyEmail:    false,
		UserTimezone:        "America/New_York",
		Subscriptions: []*am.EventSubscriptions{
			&am.EventSubscriptions{
				TypeID:              am.EventAXFR,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventCertExpiring,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventNewHost,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventNewWebsite,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
		},
	}

	eventClient.GetFn = func(ctx context.Context, userContext am.UserContext, filter *am.EventFilter) ([]*am.Event, error) {
		eventLock.Lock()
		defer eventLock.Unlock()
		cp := make([]*am.Event, 0)
		for _, v := range events {
			v.OrgID = userContext.GetOrgID()
			v.GroupID = 1
			cp = append(cp, v)
		}
		return cp, nil
	}

	eventClient.MarkReadFn = func(ctx context.Context, userContext am.UserContext, notificationIDs []int64) error {
		eventLock.Lock()
		defer eventLock.Unlock()
		for _, id := range notificationIDs {
			if _, ok := events[id]; ok {
				delete(events, id)
			}
		}
		return nil
	}

	eventClient.GetSettingsFn = func(ctx context.Context, userContext am.UserContext) (*am.UserEventSettings, error) {
		return eventSettings, nil
	}

	eventClient.UpdateSettingsFn = func(ctx context.Context, userContext am.UserContext, settings *am.UserEventSettings) error {
		eventLock.Lock()
		eventSettings = settings
		eventLock.Unlock()
		return nil
	}

	return eventClient
}

func buildOrg(userContext am.UserContext, orgName string, orgID int) *am.Organization {
	return &am.Organization{
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
		SubscriptionID:          am.SubscriptionEnterprise,
		LimitHosts:              10000,
		LimitTLD:                100,
	}
}
