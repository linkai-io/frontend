package event

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

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

func (h *EventHandlers) Get(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving notifications...")

	events, err := h.eventClient.Get(req.Context(), userContext, &am.EventFilter{Start: 0, Limit: 10, Filters: &am.FilterType{}})
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve events")
		middleware.ReturnError(w, "error retrieving notifications", 500)
		return
	}

	if data, err = json.Marshal(events); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *EventHandlers) GetSettings(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving notifications...")

	settings, err := h.eventClient.GetSettings(req.Context(), userContext)
	if err != nil {
		logger.Error().Err(err).Msg("failed to user notification settings")
		middleware.ReturnError(w, "error retrieving user notification settings", 500)
		return
	}

	if data, err = json.Marshal(settings); err != nil {
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

	if err := h.eventClient.UpdateSettings(req.Context(), userContext, settings); err != nil {
		logger.Error().Err(err).Msg("failed updating user notification settings")
		middleware.ReturnError(w, "error updating user notification settings", 400)
		return
	}

	middleware.ReturnSuccess(w, "Settings updated", 200)
}
