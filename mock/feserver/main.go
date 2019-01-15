package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
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
)

func main() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("service", "FakeServer").Logger()

	r := chi.NewRouter()
	orgClient := testOrgClient()
	addrClient := testAddrClient()
	userClient := testUserClient()
	scanGroupClient := testScanGroupClient()

	addrHandlers := address.New(addrClient, scanGroupClient)
	addrHandlers.ContextExtractor = fakeContext

	orgHandlers := org.New(orgClient)
	orgHandlers.ContextExtractor = fakeContext

	userHandlers := user.New(userClient, orgClient, &user.UserEnv{Env: "local", Region: "us-east-1"})
	userHandlers.ContextExtractor = fakeContext

	scanGroupHandlers := scangroup.New(scanGroupClient, &scangroup.ScanGroupEnv{Env: "local", Region: "us-east-1"})
	scanGroupHandlers.ContextExtractor = fakeContext
	r.NotFound(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(404)
		fmt.Fprintf(w, "%#v not found", req.URL)
	}))
	// for addresses
	r.Route("/address", func(r chi.Router) {
		r.Get("/group/{id}", addrHandlers.GetAddresses)
		r.Put("/group/{id}/initial", addrHandlers.PutInitialAddresses)
		r.Get("/group/{id}/count", addrHandlers.GetGroupCount)
	})

	// testing scangroups
	r.Route("/scangroup", func(r chi.Router) {
		r.Get("/groups", scanGroupHandlers.GetScanGroups)
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
		//r.Get("/", GetUser)
		r.Patch("/details", userHandlers.UpdateUser)
		r.Patch("/password", userHandlers.ChangePassword)
	})

	log.Info().Msg("listening on :3000")
	err := http.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}

func fakeContext(ctx context.Context) (am.UserContext, bool) {
	return &am.UserContextData{OrgID: 1, UserID: 1}, true
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

func testScanGroupClient() am.ScanGroupService {
	var newID int32
	groupLock := &sync.RWMutex{}

	groups := make(map[int]*am.ScanGroup)

	scanGroupClient := &mock.ScanGroupService{}
	scanGroupClient.GetFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, *am.ScanGroup, error) {
		groupLock.RLock()
		defer groupLock.RUnlock()

		if sg, ok := groups[groupID]; ok {
			return userContext.GetOrgID(), sg, nil
		}
		return userContext.GetOrgID(), nil, errors.New("no scan group found")
	}

	scanGroupClient.GetByNameFn = func(ctx context.Context, userContext am.UserContext, groupName string) (int, *am.ScanGroup, error) {
		groupLock.RLock()
		defer groupLock.RUnlock()

		for _, g := range groups {
			if g.GroupName == groupName {
				return userContext.GetOrgID(), g, errors.New("group name exists")
			}
		}

		return userContext.GetOrgID(), nil, errors.New("no scan group found")
	}

	scanGroupClient.GroupsFn = func(ctx context.Context, userContext am.UserContext) (oid int, groups []*am.ScanGroup, err error) {
		return userContext.GetOrgID(), groups, nil
	}

	scanGroupClient.CreateFn = func(ctx context.Context, userContext am.UserContext, newGroup *am.ScanGroup) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			if g.GroupName == newGroup.GroupName {
				return userContext.GetOrgID(), 0, errors.New("group name exists")
			}
		}
		gid := atomic.AddInt32(&newID, 1)
		newGroup.GroupID = int(gid)
		groups[int(gid)] = newGroup
		return userContext.GetOrgID(), int(gid), nil
	}
	return scanGroupClient
}

func testAddrClient() am.AddressService {
	addrClient := &mock.AddressService{}
	addrClient.GetFn = func(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (int, []*am.ScanGroupAddress, error) {
		addresses := make([]*am.ScanGroupAddress, 1)
		addresses[0] = &am.ScanGroupAddress{
			AddressID:           1,
			OrgID:               userContext.GetOrgID(),
			GroupID:             filter.GroupID,
			HostAddress:         "example.com",
			IPAddress:           "1.1.1.1",
			DiscoveryTime:       time.Now().UnixNano(),
			DiscoveredBy:        "",
			LastScannedTime:     time.Now().UnixNano(),
			LastSeenTime:        time.Now().UnixNano(),
			ConfidenceScore:     100.0,
			UserConfidenceScore: 0.0,
			IsSOA:               false,
			IsWildcardZone:      false,
			IsHostedService:     false,
			Ignored:             false,
			FoundFrom:           "",
			NSRecord:            0,
			AddressHash:         "somehash",
		}
		return userContext.GetOrgID(), addresses, nil
	}
	addrClient.CountFn = func(ctx context.Context, userContext am.UserContext, groupID int) (oid int, count int, err error) {
		return userContext.GetOrgID(), 1, nil
	}

	addrClient.UpdateFn = func(ctx context.Context, userContext am.UserContext, addresses map[string]*am.ScanGroupAddress) (oid int, count int, err error) {
		return userContext.GetOrgID(), len(addresses), nil
	}

	addrClient.DeleteFn = func(ctx context.Context, userContext am.UserContext, groupID int, addressIDs []int64) (oid int, err error) {
		return userContext.GetOrgID(), nil
	}
	return addrClient
}
