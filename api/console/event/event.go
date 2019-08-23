package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"

	"github.com/linkai-io/am/am"
)

type EventHandlers struct {
	eventClient      am.EventService
	ContextExtractor middleware.UserContextExtractor
}

func New(eventClient am.EventService) *EventHandlers {
	return &EventHandlers{
		eventClient:      eventClient,
		ContextExtractor: middleware.ExtractUserContext,
	}
}

type eventResponse struct {
	Events  []*am.Event `json:"events"`
	GroupID int         `json:"group_id"`
}

func (h *EventHandlers) Get(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving notifications...")
	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	filter, err := h.ParseGetFilterQuery(req.URL.Query(), groupID)
	if err != nil {
		logger.Error().Err(err).Msg("failed parse url query parameters")
		middleware.ReturnError(w, "invalid parameters supplied", 401)
		return
	}

	events, err := h.eventClient.Get(req.Context(), userContext, filter)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve events")
		middleware.ReturnError(w, "error retrieving notifications", 500)
		return
	}

	resp := &eventResponse{}
	resp.Events = events
	resp.GroupID = groupID

	if data, err = json.Marshal(resp); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *EventHandlers) ParseGetFilterQuery(values url.Values, groupID int) (*am.EventFilter, error) {
	filter := &am.EventFilter{
		Start:   0,
		Limit:   0,
		Filters: &am.FilterType{},
	}
	filter.Filters.AddInt32(am.FilterEventGroupID, int32(groupID))

	limit := values.Get("limit")
	if limit == "" {
		filter.Limit = 25
	} else {
		l, err := strconv.Atoi(limit)
		if err != nil {
			return nil, err
		}
		filter.Limit = int32(l)
		if filter.Limit > 5000 {
			return nil, errors.New("limit max size exceeded (5000)")
		}
	}

	return filter, nil
}

type settingsResponse struct {
	UserSettings    *am.UserEventSettings      `json:"user_settings"`
	WebhookSettings []*am.WebhookEventSettings `json:"webhook_settings,omitempty"`
}

func (h *EventHandlers) GetSettings(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	resp := &settingsResponse{}

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving webhooks and settings...")

	resp.WebhookSettings, err = h.eventClient.GetWebhooks(req.Context(), userContext)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve org webhook settings")
	}

	resp.UserSettings, err = h.eventClient.GetSettings(req.Context(), userContext)
	if err != nil {
		// hack :|
		if strings.Contains(err.Error(), "no rows in result set") {
			handleEmptySettings(w, resp)
			return
		}
		logger.Error().Err(err).Msgf("failed to user notification settings %#v", err)
		middleware.ReturnError(w, "error retrieving user notification settings", 500)
		return
	}

	if data, err = json.Marshal(resp); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

type webhookEventTest struct {
	TypeID  int32  `json:"type_id"`
	URL     string `json:"url"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func (h *EventHandlers) SendTestWebhookEvent(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving settings...")

	if data, err = json.Marshal(nil); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func handleEmptySettings(w http.ResponseWriter, resp *settingsResponse) {
	var data []byte
	var err error

	resp.UserSettings = &am.UserEventSettings{}
	if data, err = json.Marshal(resp); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

type MarkReadRequest struct {
	NotificationIDs []int64 `json:"notification_ids"`
}

func (h *EventHandlers) MarkRead(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving notifications...")

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read body")
		middleware.ReturnError(w, "error reading notification id details", 400)
		return
	}
	defer req.Body.Close()

	ids := &MarkReadRequest{}
	if err := json.Unmarshal(body, ids); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal notification ids")
		middleware.ReturnError(w, "error reading notification ids", 400)
		return
	}

	if err := h.eventClient.MarkRead(req.Context(), userContext, ids.NotificationIDs); err != nil {
		logger.Error().Err(err).Msg("failed marking notifications as read")
		middleware.ReturnError(w, "error marking notifications as read", 400)
		return
	}

	middleware.ReturnSuccess(w, "OK", 200)
}

type UserNotificationSettings struct {
	Subscriptions     []*am.EventSubscriptions `json:"subscriptions"`
	ShouldWeeklyEmail bool                     `json:"should_weekly_email"`
	ShouldDailyEmail  bool                     `json:"should_daily_email"`
	UserTimezone      string                   `json:"user_timezone"`
}

func (h *EventHandlers) UpdateSettings(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Updating notification settings...")

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read body")
		middleware.ReturnError(w, "error reading notification id details", 400)
		return
	}
	defer req.Body.Close()

	userSettings := &UserNotificationSettings{}
	if err := json.Unmarshal(body, userSettings); err != nil {
		logger.Error().Err(err).Msg("failed to update user notification settings")
		middleware.ReturnError(w, "error updating user notification settings", 400)
		return
	}

	for _, sub := range userSettings.Subscriptions {
		if _, ok := am.EventTypes[sub.TypeID]; !ok {
			logger.Error().Msg("invalid subscription type id supplied")
			middleware.ReturnError(w, "invalid subscription type id supplied", 400)
			return
		}

		if sub.Subscribed == true && sub.SubscribedTimestamp == 0 {
			sub.SubscribedTimestamp = time.Now().UnixNano()
		}

		// if they unsubscribe, reset the subscribed timestamp
		if sub.Subscribed == false {
			sub.SubscribedTimestamp = 0
		}
	}

	if _, err := time.LoadLocation(userSettings.UserTimezone); err != nil {
		logger.Error().Str("zone", userSettings.UserTimezone).Msg("invalid timezone data provided")
		middleware.ReturnError(w, "invalid timezone data provided", 400)
		return
	}

	settings := &am.UserEventSettings{
		WeeklyReportSendDay: 0,
		ShouldWeeklyEmail:   userSettings.ShouldWeeklyEmail,
		DailyReportSendHour: 0,
		UserTimezone:        userSettings.UserTimezone,
		ShouldDailyEmail:    userSettings.ShouldDailyEmail,
		Subscriptions:       userSettings.Subscriptions,
	}

	for _, sub := range userSettings.Subscriptions {
		logger.Info().Msgf("adding subscriptions: %#v", sub)
	}

	if err := h.eventClient.UpdateSettings(req.Context(), userContext, settings); err != nil {
		logger.Error().Err(err).Msg("failed updating user notification settings")
		middleware.ReturnError(w, "error updating user notification settings", 400)
		return
	}

	middleware.ReturnSuccess(w, "Settings updated", 200)
}

func groupIDFromRequest(req *http.Request) (int, error) {
	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	return id, err
}
