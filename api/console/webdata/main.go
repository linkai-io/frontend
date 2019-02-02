package webdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog/log"
)

type WebHandlers struct {
	webClient        am.WebDataService
	scanGroupClient  am.ScanGroupService
	ContextExtractor middleware.UserContextExtractor
}

func New(webClient am.WebDataService) *WebHandlers {
	return &WebHandlers{
		webClient:        webClient,
		ContextExtractor: middleware.ExtractUserContext,
	}
}

type webResponse struct {
	Responses []*am.HTTPResponse `json:"responses"`
	LastIndex int64              `json:"last_index"`
	Status    string             `json:"status"`
}

func (h *WebHandlers) GetResponses(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)
	log.Info().Msg("Retrieving responses...")
	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	filter, err := h.ParseResponseFilterQuery(req.URL.Query(), userContext.GetOrgID(), groupID)
	if err != nil {
		logger.Error().Err(err).Msg("failed parse url query parameters")
		middleware.ReturnError(w, "invalid parameters supplied", 401)
		return
	}

	oid, responses, err := h.webClient.GetResponses(req.Context(), userContext, filter)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve responses")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	var lastID int64
	for _, response := range responses {
		if response.ResponseID > lastID {
			lastID = response.ResponseID
		}
		if oid != userContext.GetOrgID() {
			logger.Error().Err(err).Msg("authorization failure")
			middleware.ReturnError(w, "failed to get responses", 500)
			return
		}
	}

	resp := &webResponse{
		LastIndex: lastID,
		Responses: responses,
		Status:    "OK",
	}

	data, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *WebHandlers) ExportResponses(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	allResponses := make([]*am.HTTPResponse, 0)

	var lastIndex int64
	for {
		filter := &am.WebResponseFilter{
			OrgID:             userContext.GetOrgID(),
			GroupID:           id,
			Start:             lastIndex,
			SinceResponseTime: time.Now().Add(time.Hour * 48).UnixNano(),
			Limit:             1000,
		}
		oid, responses, err := h.webClient.GetResponses(req.Context(), userContext, filter)
		if err != nil {
			logger.Error().Err(err).Msg("error getting websites")
			middleware.ReturnError(w, "internal error", 500)
			return
		}

		if len(responses) == 0 {
			break
		}

		var lastID int64
		for _, response := range responses {
			if response.ResponseID > lastID {
				lastID = response.ResponseID
			}

			allResponses = append(allResponses, response)

			if oid != response.OrgID {
				logger.Error().Err(err).Msg("authorization failure")
				middleware.ReturnError(w, "failed to get addresses", 500)
				return
			}
		}
		lastIndex = lastID
	}

	data, err := json.Marshal(allResponses)
	if err != nil {
		logger.Error().Err(err).Msg("error during marshal")
		middleware.ReturnError(w, "internal error during processing", 500)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=snapshots.%d.%d.json", id, time.Now().Unix()))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

type webSnapshots struct {
	Snapshots []*am.WebSnapshot `json:"snapshots"`
	LastIndex int64             `json:"last_index"`
	Status    string            `json:"status"`
}

func (h *WebHandlers) GetSnapshots(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	filter, err := h.ParseSnapshotsFilterQuery(req.URL.Query(), userContext.GetOrgID(), groupID)
	if err != nil {
		logger.Error().Err(err).Msg("failed parse url query parameters")
		middleware.ReturnError(w, "invalid parameters supplied", 401)
		return
	}

	oid, snapshots, err := h.webClient.GetSnapshots(req.Context(), userContext, filter)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve snapshots")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	var lastID int64
	for _, snapshot := range snapshots {
		if snapshot.SnapshotID > lastID {
			lastID = snapshot.SnapshotID
		}
		if oid != userContext.GetOrgID() {
			logger.Error().Err(err).Msg("authorization failure")
			middleware.ReturnError(w, "failed to get snapshots", 500)
			return
		}
	}

	resp := &webSnapshots{
		LastIndex: lastID,
		Snapshots: snapshots,
		Status:    "OK",
	}

	data, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *WebHandlers) ExportSnapshots(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	allSnapshots := make([]*am.WebSnapshot, 0)

	var lastIndex int64
	for {
		filter := &am.WebSnapshotFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: id,
			Start:   lastIndex,
			Limit:   1000,
		}
		oid, snapshots, err := h.webClient.GetSnapshots(req.Context(), userContext, filter)
		if err != nil {
			logger.Error().Err(err).Msg("error getting websites")
			middleware.ReturnError(w, "internal error", 500)
			return
		}

		if len(snapshots) == 0 {
			break
		}

		var lastID int64
		for _, snapshot := range snapshots {
			if snapshot.SnapshotID > lastID {
				lastID = snapshot.SnapshotID
			}

			allSnapshots = append(allSnapshots, snapshot)

			if oid != snapshot.OrgID {
				logger.Error().Err(err).Msg("authorization failure")
				middleware.ReturnError(w, "failed to get addresses", 500)
				return
			}
		}
		lastIndex = lastID
	}

	data, err := json.Marshal(allSnapshots)
	if err != nil {
		logger.Error().Err(err).Msg("error during marshal")
		middleware.ReturnError(w, "internal error during processing", 500)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=snapshots.%d.%d.json", id, time.Now().Unix()))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

type webCertificates struct {
	Certificates []*am.WebCertificate `json:"certificates"`
	LastIndex    int64                `json:"last_index"`
	Status       string               `json:"status"`
}

func (h *WebHandlers) GetCertificates(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	filter, err := h.ParseCertificatesFilterQuery(req.URL.Query(), userContext.GetOrgID(), groupID)
	if err != nil {
		logger.Error().Err(err).Msg("failed parse url query parameters")
		middleware.ReturnError(w, "invalid parameters supplied", 401)
		return
	}

	oid, certificates, err := h.webClient.GetCertificates(req.Context(), userContext, filter)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve certificates")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	var lastID int64
	for _, certificate := range certificates {
		if certificate.CertificateID > lastID {
			lastID = certificate.CertificateID
		}
		if oid != userContext.GetOrgID() {
			logger.Error().Err(err).Msg("authorization failure")
			middleware.ReturnError(w, "failed to get certificates", 500)
			return
		}
	}

	resp := &webCertificates{
		LastIndex:    lastID,
		Certificates: certificates,
		Status:       "OK",
	}

	data, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *WebHandlers) ExportCertificates(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	allCertificates := make([]*am.WebCertificate, 0)

	var lastIndex int64
	for {
		filter := &am.WebCertificateFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: id,
			Start:   lastIndex,
			Limit:   1000,
		}
		oid, certs, err := h.webClient.GetCertificates(req.Context(), userContext, filter)
		if err != nil {
			logger.Error().Err(err).Msg("error getting certificates")
			middleware.ReturnError(w, "internal error", 500)
			return
		}

		if len(certs) == 0 {
			break
		}

		var lastID int64
		for _, cert := range certs {
			if cert.CertificateID > lastID {
				lastID = cert.CertificateID
			}

			allCertificates = append(allCertificates, cert)

			if oid != cert.OrgID {
				logger.Error().Err(err).Msg("authorization failure")
				middleware.ReturnError(w, "failed to get addresses", 500)
				return
			}
		}
		lastIndex = lastID
	}

	data, err := json.Marshal(allCertificates)
	if err != nil {
		logger.Error().Err(err).Msg("error during marshal")
		middleware.ReturnError(w, "internal error during processing", 500)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=certificates.%d.%d.json", id, time.Now().Unix()))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *WebHandlers) ParseResponseFilterQuery(values url.Values, orgID, groupID int) (*am.WebResponseFilter, error) {
	var err error
	filter := &am.WebResponseFilter{
		OrgID:             orgID,
		GroupID:           groupID,
		WithResponseTime:  false,
		SinceResponseTime: 0,
		Start:             0,
		Limit:             0,
	}

	sinceTime := values.Get("since_response_time")
	if sinceTime != "" {
		filter.WithResponseTime = true
		filter.SinceResponseTime, err = strconv.ParseInt(sinceTime, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	start := values.Get("start")
	if start == "" {
		filter.Start = 0
	} else {
		filter.Start, err = strconv.ParseInt(start, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	limit := values.Get("limit")
	if limit == "" {
		filter.Limit = 0
	} else {
		filter.Limit, err = strconv.Atoi(limit)
		if err != nil {
			return nil, err
		}
		if filter.Limit > 1000 {
			return nil, errors.New("limit max size exceeded (1000)")
		}
	}
	return filter, nil
}

func (h *WebHandlers) ParseCertificatesFilterQuery(values url.Values, orgID, groupID int) (*am.WebCertificateFilter, error) {
	var err error
	filter := &am.WebCertificateFilter{
		OrgID:             orgID,
		GroupID:           groupID,
		WithResponseTime:  false,
		SinceResponseTime: 0,
		WithValidTo:       false,
		ValidToTime:       0,
		Start:             0,
		Limit:             0,
	}

	sinceTime := values.Get("since_response_time")
	if sinceTime != "" {
		filter.WithResponseTime = true
		filter.SinceResponseTime, err = strconv.ParseInt(sinceTime, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	validTo := values.Get("valid_to")
	if validTo != "" {
		filter.WithValidTo = true
		filter.ValidToTime, err = strconv.ParseInt(validTo, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	start := values.Get("start")
	if start == "" {
		filter.Start = 0
	} else {
		filter.Start, err = strconv.ParseInt(start, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	limit := values.Get("limit")
	if limit == "" {
		filter.Limit = 0
	} else {
		filter.Limit, err = strconv.Atoi(limit)
		if err != nil {
			return nil, err
		}
		if filter.Limit > 1000 {
			return nil, errors.New("limit max size exceeded (1000)")
		}
	}
	return filter, nil
}

func (h *WebHandlers) ParseSnapshotsFilterQuery(values url.Values, orgID, groupID int) (*am.WebSnapshotFilter, error) {
	var err error
	filter := &am.WebSnapshotFilter{
		OrgID:             orgID,
		GroupID:           groupID,
		WithResponseTime:  false,
		SinceResponseTime: 0,
		Start:             0,
		Limit:             0,
	}

	sinceTime := values.Get("since_response_time")
	if sinceTime != "" {
		filter.WithResponseTime = true
		filter.SinceResponseTime, err = strconv.ParseInt(sinceTime, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	start := values.Get("start")
	if start == "" {
		filter.Start = 0
	} else {
		filter.Start, err = strconv.ParseInt(start, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	limit := values.Get("limit")
	if limit == "" {
		filter.Limit = 0
	} else {
		filter.Limit, err = strconv.Atoi(limit)
		if err != nil {
			return nil, err
		}
		if filter.Limit > 1000 {
			return nil, errors.New("limit max size exceeded (1000)")
		}
	}
	return filter, nil
}

func groupIDFromRequest(req *http.Request) (int, error) {
	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	return id, err
}
