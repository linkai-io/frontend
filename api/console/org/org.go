package org

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/serializers"

	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
)

type OrgHandlers struct {
	orgClient        am.OrganizationService
	ContextExtractor middleware.UserContextExtractor
}

func New(orgClient am.OrganizationService) *OrgHandlers {
	return &OrgHandlers{
		orgClient:        orgClient,
		ContextExtractor: middleware.ExtractUserContext,
	}
}

func (h *OrgHandlers) GetByName(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}
	param := chi.URLParam(req, "name")
	_, org, err := h.orgClient.Get(req.Context(), userContext, param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = serializers.OrgForUsers(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *OrgHandlers) GetByID(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	_, org, err := h.orgClient.GetByID(req.Context(), userContext, id)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = serializers.OrgForUsers(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *OrgHandlers) GetByCID(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "cid")

	_, org, err := h.orgClient.GetByCID(req.Context(), userContext, param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = serializers.OrgForUsers(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *OrgHandlers) List(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte
	var filter am.OrgFilter

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	q := req.URL.Query()
	startStr := q.Get("start")
	if startStr != "" {
		filter.Start, err = strconv.Atoi(startStr)
		if err != nil {
			filter.Start = 0
		}
	}

	limitStr := q.Get("limit")
	if limitStr != "" {
		filter.Limit, err = strconv.Atoi(limitStr)
		if err != nil {
			filter.Limit = 10
		}
	}

	org, err := h.orgClient.List(req.Context(), userContext, &filter)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = json.Marshal(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *OrgHandlers) Update(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte
	org := &am.Organization{}

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}
	defer req.Body.Close()

	if err := json.Unmarshal(data, org); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}

	if _, err = h.orgClient.Update(req.Context(), userContext, org); err != nil {
		log.Error().Err(err).Msg("failed to update organization")
		middleware.ReturnError(w, "error updating organization", 500)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *OrgHandlers) Delete(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if _, err = h.orgClient.Delete(req.Context(), userContext, id); err != nil {
		log.Error().Err(err).Msg("failed to delete organization")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}
