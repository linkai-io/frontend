package main

import (
	"context"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/am/pkg/convert"
)

func testWebClient() am.WebDataService {
	webClient := &mock.WebDataService{}
	var respID int64
	var certID int64
	var snapshotID int64

	webClient.OrgStatsFn = func(ctx context.Context, userContext am.UserContext) (int, []*am.ScanGroupWebDataStats, error) {
		orgStats := make([]*am.ScanGroupWebDataStats, 2)
		for i := 0; i < 2; i++ {
			orgStats[i] = &am.ScanGroupWebDataStats{
				OrgID:               userContext.GetOrgID(),
				GroupID:             i,
				ExpiringCerts15Days: 1 * int32(i),
				ExpiringCerts30Days: 2 * int32(i),
				UniqueWebServers:    70 * int32(i),
				ServerTypes: []string{
					"Apache",
					"nginx",
					"AmazonS3",
					"IIS",
				},
				ServerCounts: []int32{
					5, 3, 10, 60,
				},
			}
		}
		return userContext.GetOrgID(), orgStats, nil
	}

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

	webClient.GetURLListFn = func(ctx context.Context, userContext am.UserContext, filter *am.WebResponseFilter) (int, []*am.URLListResponse, error) {
		if filter.Start != math.MaxInt64 {
			return userContext.GetOrgID(), make([]*am.URLListResponse, 0), nil
		}

		responses := make([]*am.URLListResponse, 2)
		id := atomic.AddInt64(&respID, 1)
		responses[0] = makeURLResponse(userContext, filter, id)
		id = atomic.AddInt64(&respID, 2)
		responses[1] = makeURLResponse(userContext, filter, id)
		return userContext.GetOrgID(), responses, nil
	}

	webClient.GetDomainDependencyFn = func(ctx context.Context, userContext am.UserContext, filter *am.WebResponseFilter) (int, *am.WebDomainDependency, error) {

		r := &am.WebDomainDependency{
			Status:    "OK",
			OrgID:     userContext.GetOrgID(),
			GroupID:   filter.GroupID,
			LastIndex: math.MaxInt64,
			Nodes: []*am.WebDomainNode{
				&am.WebDomainNode{ID: "example.com", Origin: 1},
				&am.WebDomainNode{ID: "js.com", Origin: 0},
				&am.WebDomainNode{ID: "example1.com", Origin: 1},
				&am.WebDomainNode{ID: "asdf.com", Origin: 0},
				&am.WebDomainNode{ID: "exasdfdfafample.com", Origin: 0},
			},
			Links: []*am.WebDomainLink{
				&am.WebDomainLink{Source: "example.com", Target: "js.com"},
				&am.WebDomainLink{Source: "example.com", Target: "asdf.com"},
				&am.WebDomainLink{Source: "example1.com", Target: "exasdfdfafample.com"},
				&am.WebDomainLink{Source: "example1.com", Target: "asdf.com"},
			},
		}
		return userContext.GetOrgID(), r, nil
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
	host := fmt.Sprintf("%d.example.com", respID)
	ip := fmt.Sprintf("1.1.1.%d", respID)
	return &am.WebSnapshot{
		SnapshotID:          respID,
		OrgID:               userContext.GetOrgID(),
		GroupID:             filter.GroupID,
		SnapshotLink:        "/something/something.png",
		SerializedDOMHash:   "abcd",
		SerializedDOMLink:   "/something/something",
		ResponseTimestamp:   time.Now().UnixNano(),
		IsDeleted:           false,
		URL:                 fmt.Sprintf("http://%s", host),
		AddressHash:         convert.HashAddress(ip, host),
		HostAddress:         host,
		IPAddress:           ip,
		ResponsePort:        80,
		Scheme:              "",
		TechCategories:      []string{"JavaScript Libraries", "CMS"},
		TechNames:           []string{"jQuery", "Komodo CMS"},
		TechVersions:        []string{"1.2.3", ""},
		TechMatchLocations:  []string{"javascript", "headers"},
		TechMatchData:       []string{"1.2.3", ""},
		TechIcons:           []string{"jQuery.svg", "Komodo CMS.png"},
		TechWebsites:        []string{"https://jquery.com", "http://www.komodocms.com"},
		LoadURL:             fmt.Sprintf("http://redirect.%s/", host),
		URLRequestTimestamp: time.Now().UnixNano(),
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
func makeURLResponse(userContext am.UserContext, filter *am.WebResponseFilter, respID int64) *am.URLListResponse {
	urls := make([]*am.URLData, 2)
	urls[0] = &am.URLData{
		ResponseID:  respID + 1,
		URL:         "http://google.com/font",
		RawBodyLink: "/a/b/c/d/blah",
		MimeType:    "font/ttf",
	}
	urls[1] = &am.URLData{
		ResponseID:  respID,
		URL:         "http://somethingelse.com/blah",
		RawBodyLink: "/a/b/c/d/nah",
		MimeType:    "text/html",
	}
	return &am.URLListResponse{
		OrgID:               userContext.GetOrgID(),
		GroupID:             filter.GroupID,
		URLRequestTimestamp: time.Now().Add(time.Hour * -5).UnixNano(),
		HostAddress:         fmt.Sprintf("%d.example.com", respID),
		IPAddress:           fmt.Sprintf("1.1.1.%d", respID),
		URLs:                urls,
	}
}

func makeResponse(userContext am.UserContext, filter *am.WebResponseFilter, respID int64) *am.HTTPResponse {
	host := fmt.Sprintf("%d.example.com", respID)
	ip := fmt.Sprintf("1.1.1.%d", respID)
	return &am.HTTPResponse{
		ResponseID:    respID,
		OrgID:         userContext.GetOrgID(),
		GroupID:       filter.GroupID,
		AddressHash:   convert.HashAddress(ip, host),
		Scheme:        "http",
		HostAddress:   host,
		IPAddress:     ip,
		ResponsePort:  "80",
		RequestedPort: "80",
		RequestID:     "1234",
		Status:        200,
		StatusText:    "OK",
		URL:           fmt.Sprintf("http://%d.example.com", respID),
		Headers: map[string]string{
			"cookie":         "somecookie",
			"content-length": "443",
		},
		MimeType:            "text/html",
		RawBody:             "blah",
		RawBodyLink:         "/a/a/a/a/a/abcd",
		RawBodyHash:         "abcd",
		ResponseTimestamp:   time.Now().UnixNano(),
		IsDocument:          true,
		WebCertificate:      nil,
		IsDeleted:           false,
		URLRequestTimestamp: time.Now().UnixNano(),
	}
}
