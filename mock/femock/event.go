package femock

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
)

func MockEventClient() am.EventService {
	eventClient := &mock.EventService{}
	eventLock := &sync.RWMutex{}

	events := make(map[int64]*am.Event, 14)
	events[0] = &am.Event{
		NotificationID: 0,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventAXFRID,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"ns1.example.com", "ns2.example.com"},
		Read:           false,
	}
	events[1] = &am.Event{
		NotificationID: 1,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewHostID,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"www.example.com", "test.example.com"},
		Read:           false,
	}
	events[2] = &am.Event{
		NotificationID: 2,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewWebsiteID,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"https://example.com", "443", "http://www.example.com/", "80"},
		Read:           false,
	}
	expire := time.Now().Add(24 * time.Hour)
	expireStr := strconv.FormatInt(expire.Unix(), 10)

	events[3] = &am.Event{
		NotificationID: 3,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventCertExpiringID,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"example.com", "443", expireStr},
		Read:           false,
	}
	events[4] = &am.Event{
		NotificationID: 4,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewWebTechID,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"http://example.com", "80", "jQuery", "1.2.3", "https://new.example.com/", "443", "jQuery", "1.2.4"},
		Read:           false,
	}
	events[5] = &am.Event{
		NotificationID: 5,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewOpenPortID,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"example.com", "1.1.1.1", "1.1.1.2", "8080", "example1.com", "1.1.1.1", "1.1.1.2", "8080,443"},
		Read:           false,
	}
	events[6] = &am.Event{
		NotificationID: 6,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventClosedPortID,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"example.com", "1.1.1.1", "1.1.1.1", "80", "example1.com", "1.1.1.1", "1.1.1.2", "9090"},
		Read:           false,
	}

	// JSON VERSIONS
	m, _ := json.Marshal([]*am.EventAXFR{&am.EventAXFR{Servers: []string{"ns3.example.com", "ns4.example.com"}}})
	events[7] = &am.Event{
		NotificationID: 7,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventAXFRID,
		EventTimestamp: time.Now().UnixNano(),
		JSONData:       string(m),
		Read:           false,
	}

	m, _ = json.Marshal([]*am.EventNewHost{
		&am.EventNewHost{Host: "json.example.com"},
		&am.EventNewHost{Host: "json.test.example.com"},
		&am.EventNewHost{Host: "json.something.example.com"},
	})
	events[8] = &am.Event{
		NotificationID: 8,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewHostID,
		EventTimestamp: time.Now().UnixNano(),
		JSONData:       string(m),
		Read:           false,
	}

	m, _ = json.Marshal([]*am.EventNewWebsite{
		&am.EventNewWebsite{LoadURL: "https://json.example.com", URL: "https://json.example.com/", Port: 443},
		&am.EventNewWebsite{LoadURL: "http://json.redirect.example.com", URL: "https://json.redirect.example.com:443/", Port: 443},
	})

	events[9] = &am.Event{
		NotificationID: 9,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewWebsiteID,
		EventTimestamp: time.Now().UnixNano(),
		JSONData:       string(m),
		Read:           false,
	}

	m, _ = json.Marshal([]*am.EventCertExpiring{
		&am.EventCertExpiring{SubjectName: "json.example.com", ValidTo: time.Now().Add(24 * time.Hour).Unix(), Port: 443},
	})
	events[10] = &am.Event{
		NotificationID: 10,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventCertExpiringID,
		EventTimestamp: time.Now().UnixNano(),
		JSONData:       string(m),
		Read:           false,
	}

	m, _ = json.Marshal([]*am.EventNewWebTech{
		&am.EventNewWebTech{LoadURL: "https://json.example.com", URL: "https://json.example.com/", Port: 443, TechName: "jQuery", Version: "1.2.3"},
		&am.EventNewWebTech{LoadURL: "http://json.example.com", URL: "https://json.example.com/", Port: 443, TechName: "jQuery", Version: "1.2.3"},
	})
	events[11] = &am.Event{
		NotificationID: 11,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewWebTechID,
		EventTimestamp: time.Now().UnixNano(),
		JSONData:       string(m),
		Read:           false,
	}
	m, _ = json.Marshal([]*am.EventNewOpenPort{
		&am.EventNewOpenPort{Host: "json.example.com", CurrentIP: "1.1.1.1", PreviousIP: "1.1.1.2", OpenPorts: []int32{8080, 9000}},
		&am.EventNewOpenPort{Host: "json1.example.com", CurrentIP: "1.1.1.1", PreviousIP: "1.1.1.1", OpenPorts: []int32{23, 22}},
	})
	events[12] = &am.Event{
		NotificationID: 12,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewOpenPortID,
		EventTimestamp: time.Now().UnixNano(),
		JSONData:       string(m),
		Read:           false,
	}

	m, _ = json.Marshal([]*am.EventClosedPort{
		&am.EventClosedPort{Host: "json.example.com", CurrentIP: "1.1.1.1", PreviousIP: "1.1.1.2", ClosedPorts: []int32{12, 23}},
		&am.EventClosedPort{Host: "json1.example.com", CurrentIP: "1.1.1.1", PreviousIP: "1.1.1.1", ClosedPorts: []int32{2222}},
	})

	events[13] = &am.Event{
		NotificationID: 13,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventClosedPortID,
		EventTimestamp: time.Now().UnixNano(),
		JSONData:       string(m),
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
				TypeID:              am.EventAXFRID,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventCertExpiringID,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventNewHostID,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventNewWebsiteID,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventNewOpenPortID,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventClosedPortID,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
		},
	}

	eventClient.GetFn = func(ctx context.Context, userContext am.UserContext, filter *am.EventFilter) ([]*am.Event, error) {
		eventLock.Lock()
		defer eventLock.Unlock()
		cp := make([]*am.Event, 0)
		var groupID int32
		val, ok := filter.Filters.Int32(am.FilterEventGroupID)
		if ok {
			groupID = val
		}
		for _, v := range events {
			v.OrgID = userContext.GetOrgID()
			v.GroupID = int(groupID)
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
