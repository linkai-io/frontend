package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
		r.Get("/group/{id}", addrHandlers.GetAddresses)
		r.Put("/group/{id}/initial", addrHandlers.PutInitialAddresses)
		r.Get("/group/{id}/count", addrHandlers.GetGroupCount)
		r.Post("/group/{id}/download", addrHandlers.ExportAddresses)
		r.Patch("/group/{id}/delete", addrHandlers.DeleteAddresses)
		r.Patch("/group/{id}/ignore", addrHandlers.IgnoreAddresses)
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

	r.Route("/webdata", func(r chi.Router) {
		r.Get("/group/{id}/snapshots", webHandlers.GetSnapshots)
		r.Post("/group/{id}/snapshots/download", webHandlers.ExportSnapshots)
		r.Get("/group/{id}/certificates", webHandlers.GetCertificates)
		r.Post("/group/{id}/certificates/download", webHandlers.ExportCertificates)
		r.Get("/group/{id}/responses", webHandlers.GetResponses)
		r.Post("/group/{id}/responses/download", webHandlers.ExportResponses)
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

func testWebClient() am.WebDataService {
	webClient := &mock.WebDataService{}
	var respID int64
	var certID int64
	var snapshotID int64

	webClient.GetResponsesFn = func(ctx context.Context, userContext am.UserContext, filter *am.WebResponseFilter) (int, []*am.HTTPResponse, error) {
		if filter.Start > 2 {
			return userContext.GetOrgID(), make([]*am.HTTPResponse, 0), nil
		}

		responses := make([]*am.HTTPResponse, 2)
		id := atomic.AddInt64(&respID, 1)
		responses[0] = makeResponse(userContext, filter, id)
		id = atomic.AddInt64(&respID, 1)
		responses[1] = makeResponse(userContext, filter, id)
		return userContext.GetOrgID(), responses, nil
	}

	webClient.GetCertificatesFn = func(ctx context.Context, userContext am.UserContext, filter *am.WebCertificateFilter) (int, []*am.WebCertificate, error) {
		if filter.Start > 2 {
			return userContext.GetOrgID(), make([]*am.WebCertificate, 0), nil
		}
		certs := make([]*am.WebCertificate, 2)
		id := atomic.AddInt64(&certID, 1)
		certs[0] = makeCert(userContext, filter, id)
		id = atomic.AddInt64(&certID, 1)
		certs[1] = makeCert(userContext, filter, id)
		return userContext.GetOrgID(), certs, nil
	}

	webClient.GetSnapshotsFn = func(ctx context.Context, userContext am.UserContext, filter *am.WebSnapshotFilter) (int, []*am.WebSnapshot, error) {
		if filter.Start > 2 {
			return userContext.GetOrgID(), make([]*am.WebSnapshot, 0), nil
		}
		snaps := make([]*am.WebSnapshot, 2)
		id := atomic.AddInt64(&snapshotID, 1)
		snaps[0] = makeSnapshot(userContext, filter, id)
		id = atomic.AddInt64(&snapshotID, 1)
		snaps[1] = makeSnapshot(userContext, filter, id)
		return userContext.GetOrgID(), snaps, nil
	}

	return webClient
}

func makeSnapshot(userContext am.UserContext, filter *am.WebSnapshotFilter, respID int64) *am.WebSnapshot {
	return &am.WebSnapshot{
		SnapshotID:           respID,
		OrgID:                userContext.GetOrgID(),
		GroupID:              filter.GroupID,
		AddressID:            respID,
		AddressIDHostAddress: fmt.Sprintf("%d.example.com", respID),
		AddressIDIPAddress:   fmt.Sprintf("1.1.1.%d", respID),
		SnapshotLink:         "/something/something.png",
		SerializedDOMHash:    "abcd",
		SerializedDOMLink:    "/something/something",
		ResponseTimestamp:    time.Now().UnixNano(),
		IsDeleted:            false,
	}
}

func makeCert(userContext am.UserContext, filter *am.WebCertificateFilter, respID int64) *am.WebCertificate {
	return &am.WebCertificate{
		OrgID:                             userContext.GetOrgID(),
		GroupID:                           filter.GroupID,
		CertificateID:                     respID,
		ResponseTimestamp:                 time.Now().UnixNano(),
		HostAddress:                       fmt.Sprintf("%d.example.com", respID),
		Port:                              "443",
		Protocol:                          "TLS 1.2",
		KeyExchange:                       "ECDHE_RSA",
		KeyExchangeGroup:                  "P-256",
		Cipher:                            "AES_128_GCM",
		Mac:                               "",
		CertificateValue:                  0,
		SubjectName:                       fmt.Sprintf("%d.example.com", respID),
		SanList:                           []string{fmt.Sprintf("%d.example.com", respID)},
		Issuer:                            "Amazon",
		ValidFrom:                         1535328000,
		ValidTo:                           1569585600,
		CertificateTransparencyCompliance: "unknown",
		IsDeleted:                         false,
	}
}

func makeResponse(userContext am.UserContext, filter *am.WebResponseFilter, respID int64) *am.HTTPResponse {
	return &am.HTTPResponse{
		ResponseID:           respID,
		OrgID:                userContext.GetOrgID(),
		GroupID:              filter.GroupID,
		AddressID:            1,
		AddressIDHostAddress: fmt.Sprintf("%d.example.com", respID),
		AddressIDIPAddress:   fmt.Sprintf("1.1.1.%d", respID),
		Scheme:               "http",
		HostAddress:          fmt.Sprintf("%d.example.com", respID),
		IPAddress:            fmt.Sprintf("1.1.1.%d", respID),
		ResponsePort:         "80",
		RequestedPort:        "80",
		RequestID:            "1234",
		Status:               200,
		StatusText:           "OK",
		URL:                  fmt.Sprintf("http://%d.example.com", respID),
		Headers: map[string]string{
			"cookie":         "somecookie",
			"content-length": "443",
		},
		MimeType:          "text/html",
		RawBody:           "blah",
		RawBodyLink:       "/a/a/a/a/a/abcd",
		RawBodyHash:       "abcd",
		ResponseTimestamp: time.Now().UnixNano(),
		IsDocument:        true,
		WebCertificate:    nil,
		IsDeleted:         false,
	}
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
		return userContext.GetOrgID(), nil, am.ErrScanGroupNotExists
	}

	scanGroupClient.GetByNameFn = func(ctx context.Context, userContext am.UserContext, groupName string) (int, *am.ScanGroup, error) {
		groupLock.RLock()
		defer groupLock.RUnlock()

		for _, g := range groups {
			if g.GroupName == groupName {
				return userContext.GetOrgID(), g, nil
			}
		}

		return userContext.GetOrgID(), nil, am.ErrScanGroupNotExists
	}

	scanGroupClient.GroupsFn = func(ctx context.Context, userContext am.UserContext) (int, []*am.ScanGroup, error) {
		groupLock.RLock()
		defer groupLock.RUnlock()
		allGroups := make([]*am.ScanGroup, 0)
		for _, g := range groups {
			if g.Deleted {
				continue
			}
			allGroups = append(allGroups, g)
		}
		return userContext.GetOrgID(), allGroups, nil
	}

	scanGroupClient.CreateFn = func(ctx context.Context, userContext am.UserContext, newGroup *am.ScanGroup) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Str("group", g.GroupName).Str("new", newGroup.GroupName)
			if g.GroupName == newGroup.GroupName {
				return userContext.GetOrgID(), 0, errors.New("group name exists")
			}
		}
		gid := atomic.AddInt32(&newID, 1)
		newGroup.GroupID = int(gid)
		groups[int(gid)] = newGroup
		log.Info().Int("len", len(groups)).Msg("created new group")
		return userContext.GetOrgID(), int(gid), nil
	}

	scanGroupClient.UpdateFn = func(ctx context.Context, userContext am.UserContext, updatedGroup *am.ScanGroup) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Str("group", g.GroupName).Str("new", updatedGroup.GroupName)
			if g.GroupID == updatedGroup.GroupID {
				g = updatedGroup
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}

	scanGroupClient.PauseFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Int("group_id", g.GroupID).Int("requested_gid", groupID)
			if g.GroupID == groupID {
				g.Paused = true
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}

	scanGroupClient.ResumeFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Int("group_id", g.GroupID).Int("requested_gid", groupID)
			if g.GroupID == groupID {
				g.Paused = false
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}

	scanGroupClient.DeleteFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Int("group_id", g.GroupID).Int("requested_gid", groupID)
			if g.GroupID == groupID {
				g.Deleted = true
				g.GroupName = fmt.Sprintf("%s%d", g.GroupName, time.Now().UnixNano())
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}
	return scanGroupClient
}

func testAddrClient() am.AddressService {
	addrClient := &mock.AddressService{}
	allAddresses := make(map[int64]*am.ScanGroupAddress)
	addrLock := &sync.RWMutex{}
	var addrID int64
	atomic.AddInt64(&addrID, 1)

	addrClient.GetFn = func(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (int, []*am.ScanGroupAddress, error) {
		addrLock.RLock()
		defer addrLock.RUnlock()
		addresses := make([]*am.ScanGroupAddress, 0)
		i := 0
		log.Info().Msgf("GETTING ADDRS: %#v", filter)
		sortedKeys := make([]int64, 0)

		for addrID, addr := range allAddresses {
			if filter.GroupID != addr.GroupID {
				continue
			}
			sortedKeys = append(sortedKeys, addrID)
		}
		sort.Slice(sortedKeys, func(i, j int) bool { return sortedKeys[i] < sortedKeys[j] })

		for _, key := range sortedKeys {
			addr := allAddresses[key]
			if filter.Limit < i {
				log.Info().Msgf("limit %d i %d", filter.Limit, i)
				break
			}

			if addr.AddressID > filter.Start && filter.Limit > i {
				log.Info().Msgf("adding addr %#v", addr)
				addresses = append(addresses, addr)
				i++
			}
		}

		return userContext.GetOrgID(), addresses, nil
	}

	addrClient.CountFn = func(ctx context.Context, userContext am.UserContext, groupID int) (oid int, count int, err error) {
		addrLock.RLock()
		defer addrLock.RUnlock()
		i := 0
		for _, addr := range allAddresses {
			if addr.GroupID == groupID {
				i++
			}
		}
		return userContext.GetOrgID(), i, nil
	}

	addrClient.UpdateFn = func(ctx context.Context, userContext am.UserContext, addresses map[string]*am.ScanGroupAddress) (oid int, count int, err error) {
		addrLock.Lock()
		defer addrLock.Unlock()
		for _, addr := range addresses {
			log.Info().Msgf("adding %#v", addr)
			if addr.AddressID == 0 {
				newID := atomic.AddInt64(&addrID, 1)
				addr.AddressID = newID
				allAddresses[newID] = addr
			} else {
				allAddresses[addr.AddressID] = addr
			}
		}
		log.Info().Msg("updated addresses")
		return userContext.GetOrgID(), len(addresses), nil
	}

	addrClient.DeleteFn = func(ctx context.Context, userContext am.UserContext, groupID int, addressIDs []int64) (oid int, err error) {
		addrLock.Lock()
		defer addrLock.Unlock()
		for _, id := range addressIDs {
			delete(allAddresses, id)
		}
		return userContext.GetOrgID(), nil
	}

	addrClient.IgnoreFn = func(ctx context.Context, userContext am.UserContext, groupID int, addressIDs []int64, ignoreValue bool) (oid int, err error) {
		addrLock.Lock()
		defer addrLock.Unlock()
		for _, id := range addressIDs {
			allAddresses[id].Ignored = ignoreValue
		}
		return userContext.GetOrgID(), nil
	}
	return addrClient
}
