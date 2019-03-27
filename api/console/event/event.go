package event

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

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

	events, err := h.eventClient.Get(req.Context(), userContext, &am.EventFilter{Start: 0, Limit: 1000, Filters: &am.FilterType{}})
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

func (h *EventHandlers) UpdateSettings(w http.ResponseWriter, req *http.Request) {
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

	settings := &am.UserEventSettings{}
	if err := json.Unmarshal(body, settings); err != nil {
		logger.Error().Err(err).Msg("failed to update user notification settings")
		middleware.ReturnError(w, "error updating user notification settings", 400)
		return
	}

	if err := h.eventClient.UpdateSettings(req.Context(), userContext, settings); err != nil {
		logger.Error().Err(err).Msg("failed updating user notification settings")
		middleware.ReturnError(w, "error updating user notification settings", 400)
		return
	}

	middleware.ReturnSuccess(w, "OK", 200)
}
