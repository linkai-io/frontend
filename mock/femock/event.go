package femock

import (
	"context"
	"sync"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
)

func MockEventClient() am.EventService {
	eventClient := &mock.EventService{}
	eventLock := &sync.RWMutex{}

	events := make(map[int64]*am.Event, 7)
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
	events[4] = &am.Event{
		NotificationID: 4,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewWebTech,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"http://example.com", "80", "jQuery", "1.2.3", "https://new.example.com", "443", "jQuery", "1.2.4"},
		Read:           false,
	}
	events[5] = &am.Event{
		NotificationID: 5,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventNewOpenPort,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"example.com", "1.1.1.1", "1.1.1.2", "8080", "example1.com", "1.1.1.1", "1.1.1.2", "8080,443"},
		Read:           false,
	}
	events[6] = &am.Event{
		NotificationID: 6,
		OrgID:          0,
		GroupID:        0,
		TypeID:         am.EventClosedPort,
		EventTimestamp: time.Now().UnixNano(),
		Data:           []string{"example.com", "1.1.1.1", "1.1.1.1", "80", "example1.com", "1.1.1.1", "1.1.1.2", "9090"},
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
			&am.EventSubscriptions{
				TypeID:              am.EventNewOpenPort,
				SubscribedTimestamp: time.Now().UnixNano(),
				Subscribed:          true,
			},
			&am.EventSubscriptions{
				TypeID:              am.EventClosedPort,
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
