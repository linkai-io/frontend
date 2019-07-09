package scangroup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/linkai-io/am/amtest"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/frontend/api/console/address"
	"github.com/linkai-io/frontend/api/console/scangroup"
	"github.com/linkai-io/frontend/fetest"
	"github.com/linkai-io/frontend/pkg/middleware"
	validator "gopkg.in/go-playground/validator.v9"
)

func TestVerifyWebScanPorts(t *testing.T) {
	tcpPorts := []int32{80, 443, 21, 22}
	webPorts := []int32{80, 443}
	web, tcp, valid := scangroup.VerifyWebScanPorts(webPorts, tcpPorts)
	if !valid {
		t.Fatalf("invalid ports")
	}
	t.Logf("%#v\n", web)
	amtest.SortEqualInt32(tcpPorts, tcp, t)
	amtest.SortEqualInt32(webPorts, web, t)
	t.Logf("%#v\n", tcp)
}

func TestNewGroupValidators(t *testing.T) {
	validate := validator.New()
	validate.RegisterValidation("subdomain", scangroup.ValidateSubDomain)

	var er struct {
		groupName  bool
		sub2       bool
		sub3       bool
		sub4       bool
		port2      bool
		port3      bool
		concurrent bool
		archive    bool
	}
	newGroup := &scangroup.ScanGroupDetails{}
	newGroup.GroupName = "test/"
	domains := []string{"ok", "日本", ")@#asdbadf", "bad.bad", "bad,"}
	newGroup.CustomSubNames = domains
	newGroup.ConcurrentRequests = 100
	newGroup.ArchiveAfterDays = 100
	newGroup.CustomWebPorts = []int32{1, 65535, 90000, 0}

	err := validate.Struct(newGroup)
	if err == nil {
		t.Fatalf("should have got error on validation")
	}

	for _, v := range err.(validator.ValidationErrors) {
		switch v.Field() {
		case "GroupName":
			er.groupName = true
		case "CustomSubNames[0]", "CustomSubNames[1]":
			t.Fatalf("got error when should not have %s", v.Field())
		case "CustomSubNames[2]":
			er.sub2 = true
		case "CustomSubNames[3]":
			er.sub3 = true
		case "CustomSubNames[4]":
			er.sub4 = true
		case "CustomWebPorts[0]", "CustomWebPorts[1]":
			t.Fatalf("got error on ports when should not have")
		case "CustomWebPorts[2]":
			er.port2 = true
		case "CustomWebPorts[3]":
			er.port3 = true
		case "ConcurrentRequests":
			er.concurrent = true
		case "ArchiveAfterDays":
			er.archive = true
		}
		t.Logf("error! %#v", v)
	}
	if !er.groupName || !er.sub2 || !er.sub3 || !er.sub4 || !er.port2 || !er.port3 || !er.concurrent || !er.archive {
		t.Fatalf("%#v\n", er)
	}

	validGroup := &scangroup.ScanGroupDetails{}
	validGroup.GroupName = "日本"
	validGroup.CustomSubNames = []string{"ok", "日本", "some", "domain"}
	validGroup.ConcurrentRequests = 5
	validGroup.ArchiveAfterDays = 5
	validGroup.CustomWebPorts = []int32{80, 443, 8080, 9000, 9200, 8443, 8555}
	if err := validate.Struct(validGroup); err != nil {
		t.Fatalf("should not have got error on validation: %#v\n", err)
	}
}

func testUserClient() am.UserService {
	userClient := &mock.UserService{}
	userClient.GetFn = func(ctx context.Context, userContext am.UserContext, userEmail string) (int, *am.User, error) {
		return userContext.GetOrgID(), &am.User{
			OrgID:                      userContext.GetOrgID(),
			OrgCID:                     userContext.GetOrgCID(),
			UserCID:                    userContext.GetUserCID(),
			UserID:                     userContext.GetUserID(),
			UserEmail:                  "test@test.com",
			FirstName:                  "test",
			LastName:                   "test",
			StatusID:                   am.UserStatusActive,
			CreationTime:               time.Now().UnixNano(),
			Deleted:                    false,
			AgreementAccepted:          true,
			AgreementAcceptedTimestamp: 0}, nil

	}
	userClient.GetByCIDFn = func(ctx context.Context, userContext am.UserContext, userCID string) (int, *am.User, error) {
		return userContext.GetOrgID(), &am.User{
			OrgID:                      userContext.GetOrgID(),
			OrgCID:                     userContext.GetOrgCID(),
			UserCID:                    userCID,
			UserID:                     userContext.GetUserID(),
			UserEmail:                  "test@test.com",
			FirstName:                  "test",
			LastName:                   "test",
			StatusID:                   am.UserStatusActive,
			CreationTime:               time.Now().UnixNano(),
			Deleted:                    false,
			AgreementAccepted:          true,
			AgreementAcceptedTimestamp: 0}, nil

	}
	return userClient
}

func testOrgClient() am.OrganizationService {
	orgClient := &mock.OrganizationService{}

	orgClient.GetByCIDFn = func(ctx context.Context, userContext am.UserContext, orgCID string) (int, *am.Organization, error) {
		return userContext.GetOrgID(), &am.Organization{
			OrgID:           userContext.GetOrgID(),
			OrgCID:          userContext.GetOrgCID(),
			OwnerEmail:      "test@test.com",
			FirstName:       "test",
			LastName:        "test",
			StatusID:        am.UserStatusActive,
			CreationTime:    time.Now().UnixNano(),
			Deleted:         false,
			PortScanEnabled: true,
		}, nil
	}
	return orgClient
}
func TestNewGroupSubscriptionLevels(t *testing.T) {
	scanGroupClient := &mock.ScanGroupService{}

	scanGroupClient.CreateFn = func(ctx context.Context, userContext am.UserContext, newGroup *am.ScanGroup) (oid int, gid int, err error) {
		return userContext.GetOrgID(), 1, nil
	}

	scanGroupClient.GetByNameFn = func(ctx context.Context, userContext am.UserContext, groupName string) (oid int, group *am.ScanGroup, err error) {
		return 0, nil, am.ErrScanGroupNotExists
	}

	scanGroupClient.GroupsFn = func(ctx context.Context, userContext am.UserContext) (oid int, groups []*am.ScanGroup, err error) {
		return userContext.GetOrgID(), make([]*am.ScanGroup, 0), nil
	}

	scanGroupHandlers := scangroup.New(scanGroupClient, testUserClient(), testOrgClient(), &scangroup.ScanGroupEnv{"dev", "us-east-1"})

	scanGroupHandlers.ContextExtractor = func(ctx context.Context) (am.UserContext, bool) {
		return &am.UserContextData{UserID: 1, OrgID: 1, SubscriptionID: 101}, true
	}

	r := chi.NewRouter()
	r.Route("/scangroup", func(r chi.Router) {
		r.Get("/groups", scanGroupHandlers.GetScanGroups)
		r.Get("/groups/stats", scanGroupHandlers.GetGroupStats)
		r.Get("/name/{name}", scanGroupHandlers.GetScanGroupByName)
		r.Post("/name/{name}", scanGroupHandlers.CreateScanGroup)
		r.Patch("/name/{name}", scanGroupHandlers.UpdateScanGroup)
		r.Delete("/name/{name}", scanGroupHandlers.DeleteScanGroup)
		r.Patch("/name/{name}/status", scanGroupHandlers.UpdateScanGroupStatus)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	validGroup := &scangroup.ScanGroupDetails{}
	validGroup.GroupName = "日本"
	validGroup.CustomSubNames = []string{"ok", "日本", "some", "domain"}
	validGroup.ConcurrentRequests = 5
	validGroup.ArchiveAfterDays = 5
	validGroup.CustomWebPorts = []int32{80, 443, 8080, 9000, 9200, 8443, 8555}
	validGroup.TCPPorts = []int32{20, 21, 80, 443, 8080, 9000, 9200, 8443, 8555}
	validGroup.AllowedHosts = []string{"test.com"}

	data, err := json.Marshal(validGroup)
	if err != nil {
		t.Fatalf("error marshalling: %v\n", err)
	}
	group := bytes.NewReader(data)
	rr, body := fetest.RouterTestRequest(t, ts, "POST", "/scangroup/name/test", group)
	// Check the status code is what we expect.
	if status := rr.StatusCode; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	t.Logf("%s\n", string(body))
	resp := &address.PutResponse{}
	if err := json.Unmarshal([]byte(body), resp); err != nil {
		t.Fatalf("error getting addr data: %s\n", err)
	}

	if resp.Status != "OK" {
		t.Logf("%#v\n", resp)
		t.Fatalf("expected OK response: %v\n", resp.Status)
	}

	// should error
	scanGroupClient.GroupsFn = func(ctx context.Context, userContext am.UserContext) (oid int, groups []*am.ScanGroup, err error) {
		return userContext.GetOrgID(), make([]*am.ScanGroup, 1), nil
	}
	rr, body = fetest.RouterTestRequest(t, ts, "POST", "/scangroup/name/test", group)
	// Check the status code is what we expect.
	if status := rr.StatusCode; status != 400 {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, 400)
	}

	t.Logf("%s\n", string(body))
	resp = &address.PutResponse{}
	if err := json.Unmarshal([]byte(body), resp); err != nil {
		t.Fatalf("error getting addr data: %s\n", err)
	}

	if resp.Status != "error" {
		t.Logf("%#v\n", resp)
		t.Fatalf("expected error response: %v\n", resp.Status)
	}
}

func TestDeleteGroupSubscriptionLevels(t *testing.T) {
	scanGroupClient := &mock.ScanGroupService{}

	scanGroupClient.CreateFn = func(ctx context.Context, userContext am.UserContext, newGroup *am.ScanGroup) (oid int, gid int, err error) {
		return userContext.GetOrgID(), 1, nil
	}

	scanGroupClient.GetByNameFn = func(ctx context.Context, userContext am.UserContext, groupName string) (oid int, group *am.ScanGroup, err error) {
		return 0, nil, am.ErrScanGroupNotExists
	}

	scanGroupClient.GroupsFn = func(ctx context.Context, userContext am.UserContext) (oid int, groups []*am.ScanGroup, err error) {
		return userContext.GetOrgID(), make([]*am.ScanGroup, 0), nil
	}

	scanGroupHandlers := scangroup.New(scanGroupClient, testUserClient(), testOrgClient(), &scangroup.ScanGroupEnv{"dev", "us-east-1"})

	scanGroupHandlers.ContextExtractor = func(ctx context.Context) (am.UserContext, bool) {
		return &am.UserContextData{UserID: 1, OrgID: 1, SubscriptionID: 101}, true
	}

	r := chi.NewRouter()
	r.Route("/scangroup", func(r chi.Router) {
		r.Get("/groups", scanGroupHandlers.GetScanGroups)
		r.Get("/groups/stats", scanGroupHandlers.GetGroupStats)
		r.Get("/name/{name}", scanGroupHandlers.GetScanGroupByName)
		r.Post("/name/{name}", scanGroupHandlers.CreateScanGroup)
		r.Patch("/name/{name}", scanGroupHandlers.UpdateScanGroup)
		r.Delete("/name/{name}", scanGroupHandlers.DeleteScanGroup)
		r.Patch("/name/{name}/status", scanGroupHandlers.UpdateScanGroupStatus)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	validGroup := &scangroup.ScanGroupDetails{}
	validGroup.GroupName = "日本"
	validGroup.CustomSubNames = []string{"ok", "日本", "some", "domain"}
	validGroup.ConcurrentRequests = 5
	validGroup.CustomWebPorts = []int32{80, 443, 8080, 9000, 9200, 8443, 8555}
	data, err := json.Marshal(validGroup)
	if err != nil {
		t.Fatalf("error marshalling: %v\n", err)
	}
	group := bytes.NewReader(data)
	rr, body := fetest.RouterTestRequest(t, ts, "DELETE", "/scangroup/name/test", group)
	// Check the status code is what we expect.
	if status := rr.StatusCode; status != 400 {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, 400)
	}

	t.Logf("%s\n", string(body))
	resp := &middleware.WebResponse{}
	if err := json.Unmarshal([]byte(body), resp); err != nil {
		t.Fatalf("error getting data: %s\n", err)
	}

	if resp.Status != "error" {
		t.Logf("%#v\n", resp)
		t.Fatalf("expected error response: %v\n", resp.Status)
	}
}
