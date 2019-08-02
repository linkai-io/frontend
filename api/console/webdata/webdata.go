package webdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog/log"
)

type WebDataStatsResponse struct {
	Stats  []*am.ScanGroupWebDataStats `json:"stats"`
	Status string                      `json:"status"`
}

type WebHandlers struct {
	webClient        am.WebDataService
	scanGroupClient  am.ScanGroupService
	ContextExtractor middleware.UserContextExtractor
}

func New(webClient am.WebDataService, sgClient am.ScanGroupService) *WebHandlers {
	return &WebHandlers{
		webClient:        webClient,
		scanGroupClient:  sgClient,
		ContextExtractor: middleware.ExtractUserContext,
	}
}

func (h *WebHandlers) OrgStats(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving responses...")

	oid, stats, err := h.webClient.OrgStats(req.Context(), userContext)
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

	resp := &WebDataStatsResponse{
		Status: "OK",
		Stats:  stats,
	}

	data, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

type urlListResponse struct {
	Responses []*am.URLListResponse `json:"responses"`
	LastIndex int64                 `json:"last_index"`
	Status    string                `json:"status"`
}

func (h *WebHandlers) GetURLList(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Retrieving urls...")
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

	oid, responses, err := h.webClient.GetURLList(req.Context(), userContext, filter)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve url list")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	var lastIndex int64
	lastIndex = math.MaxInt64
	for _, response := range responses {
		if oid != response.OrgID {
			logger.Error().Err(err).Msg("authorization failure")
			middleware.ReturnError(w, "failed to get url list", 500)
			return
		}

		if response.URLRequestTimestamp < lastIndex {
			lastIndex = response.URLRequestTimestamp
		}
	}

	// if we 'went past the end' reset it back to the last index we had.
	if lastIndex == math.MaxInt64 {
		lastIndex = filter.Start
	}

	resp := &urlListResponse{
		LastIndex: lastIndex,
		Responses: responses,
		Status:    "OK",
	}

	data, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))

}

func (h *WebHandlers) GetDomainDependencies(w http.ResponseWriter, req *http.Request) {
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

	_, group, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting scan group", 500)
		return
	}

	fromTime := time.Now()
	if group.Paused {
		fromTime = time.Unix(0, group.LastPausedTime)
	}

	uniqueNodes := make(map[string]struct{}, 0)
	uniqueLinks := make(map[string]struct{}, 0)
	dependencies := &am.WebDomainDependency{
		Nodes:   make([]*am.WebDomainNode, 0),
		Links:   make([]*am.WebDomainLink, 0),
		GroupID: groupID,
	}

	var lastIndex int64
	lastIndex = math.MaxInt64
	linkLimitPerRequest := 3000
	firstRequest := true
	for {
		filters := &am.FilterType{}
		filters.AddInt64(am.FilterWebAfterURLRequestTime, fromTime.Add(time.Hour*-(2*24)).UnixNano())
		filters.AddBool("is_domain_dependency", true)
		filter := &am.WebResponseFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: groupID,
			Start:   lastIndex,
			Filters: filters,
			Limit:   linkLimitPerRequest,
		}
		logger.Info().Int64("lastIndex", lastIndex).Msg("Retrieving urls for domain dependencies...")

		_, deps, err := h.webClient.GetDomainDependency(req.Context(), userContext, filter)
		if err != nil {
			logger.Error().Err(err).Msg("error getting websites")
			middleware.ReturnError(w, "internal error", 500)
			return
		}

		if len(deps.Nodes) == 0 {
			logger.Info().Msg("No more deps...")
			break
		}

		if deps.OrgID != userContext.GetOrgID() {
			logger.Error().Err(am.ErrOrgIDMismatch).Int("deps.OrgID", deps.OrgID).Msg("authorization failure")
			middleware.ReturnError(w, "internal error", 500)
			return
		}

		// we don't need to bother copying to a different structure because we have everything after the first request
		if len(deps.Links) < linkLimitPerRequest && firstRequest {
			logger.Info().Int("num domains", len(deps.Links)).Msg("got all dependencies in one request")
			dependencies = deps
			break
		}
		firstRequest = false

		if deps.LastIndex < lastIndex {
			lastIndex = deps.LastIndex
		}

		for _, node := range deps.Nodes {
			if _, ok := uniqueNodes[node.ID]; !ok {
				uniqueNodes[node.ID] = struct{}{}
				dependencies.Nodes = append(dependencies.Nodes, &am.WebDomainNode{ID: node.ID, Origin: node.Origin})
			}
		}

		for _, link := range deps.Links {
			if _, ok := uniqueLinks[link.Source+link.Target]; !ok {
				uniqueLinks[link.Source+link.Target] = struct{}{}
				dependencies.Links = append(dependencies.Links, &am.WebDomainLink{Source: link.Source, Target: link.Target})
			}
		}

		// if we have less than filter.Limit links, we have everything
		if len(deps.Links) < linkLimitPerRequest {
			break
		}
	}

	dependencies.Status = "OK"
	data, _ := json.Marshal(dependencies)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
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
	logger.Info().Msg("Retrieving responses...")
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

	var lastIndex int64
	lastIndex = math.MaxInt64
	for _, response := range responses {
		if response.ResponseID < lastIndex {
			lastIndex = response.ResponseID
		}

		if oid != response.OrgID {
			logger.Error().Err(err).Msg("authorization failure")
			middleware.ReturnError(w, "failed to get addresses", 500)
			return
		}
	}

	// if we 'went past the end' reset it back to the last index we had.
	if lastIndex == math.MaxInt64 {
		lastIndex = filter.Start
	}

	resp := &webResponse{
		LastIndex: lastIndex,
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

	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	_, group, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting scan group", 500)
		return
	}

	fromTime := time.Now()
	if group.Paused {
		fromTime = time.Unix(0, group.LastPausedTime)
	}

	allResponses := make([]*am.HTTPResponse, 0)

	var lastIndex int64
	lastIndex = math.MaxInt64
	for {
		filters := &am.FilterType{}
		filters.AddInt64(am.FilterWebAfterResponseTime, fromTime.Add(time.Hour*48).UnixNano())
		filter := &am.WebResponseFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: groupID,
			Start:   lastIndex,
			Filters: filters,
			Limit:   1000,
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

		for _, response := range responses {
			if response.ResponseID < lastIndex {
				lastIndex = response.ResponseID
			}

			allResponses = append(allResponses, response)

			if oid != response.OrgID {
				logger.Error().Err(err).Msg("authorization failure")
				middleware.ReturnError(w, "failed to get addresses", 500)
				return
			}
		}
	}

	data, err := json.Marshal(allResponses)
	if err != nil {
		logger.Error().Err(err).Msg("error during marshal")
		middleware.ReturnError(w, "internal error during processing", 500)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=snapshots.%d.%d.json", groupID, time.Now().Unix()))
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

	_, group, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting scan group", 500)
		return
	}

	fromTime := time.Now()
	if group.Paused {
		fromTime = time.Unix(0, group.LastPausedTime)
	}

	filter, err := h.ParseSnapshotsFilterQuery(req.URL.Query(), userContext.GetOrgID(), groupID, fromTime)
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

	var lastIndex int64
	lastIndex = math.MaxInt64
	for _, snapshot := range snapshots {
		if snapshot.URLRequestTimestamp < lastIndex {
			lastIndex = snapshot.URLRequestTimestamp
		}
		if oid != userContext.GetOrgID() {
			logger.Error().Err(err).Msg("authorization failure")
			middleware.ReturnError(w, "failed to get snapshots", 500)
			return
		}
	}

	// if we 'went past the end' reset it back to the last index we had.
	if lastIndex == math.MaxInt64 {
		lastIndex = filter.Start
	}

	resp := &webSnapshots{
		LastIndex: lastIndex,
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

	groupID, err := groupIDFromRequest(req)
	if err != nil {
		logger.Error().Err(err).Msg("failed getting group id")
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	_, group, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting scan group", 500)
		return
	}

	fromTime := time.Now()
	if group.Paused {
		fromTime = time.Unix(0, group.LastPausedTime)
	}

	queryFilter, err := h.ParseSnapshotsFilterQuery(req.URL.Query(), userContext.GetOrgID(), groupID, fromTime)
	if err != nil {
		logger.Error().Err(err).Msg("failed parse url query parameters")
		middleware.ReturnError(w, "invalid parameters supplied", 401)
		return
	}

	allSnapshots := make([]*am.WebSnapshot, 0)

	var lastIndex int64
	for {
		filter := &am.WebSnapshotFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: groupID,
			Start:   lastIndex,
			Limit:   1000,
			Filters: &am.FilterType{},
		}

		filter.Filters = queryFilter.Filters
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
		lastID = math.MaxInt64
		for _, snapshot := range snapshots {
			if snapshot.URLRequestTimestamp < lastID {
				lastID = snapshot.URLRequestTimestamp
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

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=snapshots.%d.%d.json", groupID, time.Now().Unix()))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

type TechDataEntry struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
}

type TechDetails struct {
	Website  string `json:"website"`
	Icon     string `json:"icon"`
	Category string `json:"category"`
}

func (t *TechDataEntry) Hash(techName string) string {
	return fmt.Sprintf("%s%s%s%d", techName, t.Version, t.URL, t.Port)
}

type TechDataResponse struct {
	Technologies map[string][]*TechDataEntry `json:"technologies"`
	TechDetails  map[string]*TechDetails     `json:"tech_details"`
}

func (h *WebHandlers) GetTechData(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)
	logger.Info().Msg("Getting TechData")
	groupID, err := groupIDFromRequest(req)
	if err != nil {
		logger.Error().Err(err).Msg("failed getting group id")
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	_, group, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting scan group", 500)
		return
	}

	fromTime := time.Now()
	if group.Paused {
		fromTime = time.Unix(0, group.LastPausedTime)
	}

	techData := &TechDataResponse{}
	techData.Technologies = make(map[string][]*TechDataEntry, 0)
	techData.TechDetails = make(map[string]*TechDetails, 0)

	// ugh i know
	hashes := make(map[string]struct{})

	var lastIndex int64
	for {
		filter := &am.WebSnapshotFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: groupID,
			Start:   lastIndex,
			Limit:   1000,
			Filters: &am.FilterType{},
		}
		filter.Filters.AddInt64(am.FilterWebAfterResponseTime, fromTime.Add(time.Hour*(-24*7)).UnixNano()) // only search past 7 days
		oid, snapshots, err := h.webClient.GetSnapshots(req.Context(), userContext, filter)
		if err != nil {
			logger.Error().Err(err).Msg("error getting snapshots for tech data")
			middleware.ReturnError(w, "internal error", 500)
			return
		}
		logger.Info().Int("snapshots_length", len(snapshots)).Msg("got records")
		if len(snapshots) == 0 {
			break
		}

		var lastID int64
		lastID = math.MaxInt64
		for _, snapshot := range snapshots {
			if snapshot.URLRequestTimestamp < lastID {
				lastID = snapshot.URLRequestTimestamp
			}

			if oid != snapshot.OrgID {
				logger.Error().Err(err).Msg("authorization failure")
				middleware.ReturnError(w, "failed to get tech data", 500)
				return
			}

			if len(snapshot.TechNames) != len(snapshot.TechIcons) && len(snapshot.TechVersions) != len(snapshot.TechNames) {
				logger.Warn().Str("host", snapshot.HostAddress).Msg("tech slice sizes were not the same, skipping")
				continue
			}

			for i, tech := range snapshot.TechNames {
				// TODO: figure out how this is empty... (different apps.jsons?)
				if tech == "" {
					continue
				}
				if _, ok := techData.Technologies[tech]; !ok {
					techData.Technologies[tech] = make([]*TechDataEntry, 0)
					techData.TechDetails[tech] = &TechDetails{}
				}

				entry := &TechDataEntry{
					Host:    snapshot.HostAddress,
					URL:     snapshot.LoadURL,
					IP:      snapshot.IPAddress,
					Port:    snapshot.ResponsePort,
					Version: snapshot.TechVersions[i],
				}
				// skip if we already have this entry
				if _, ok := hashes[entry.Hash(tech)]; ok {
					continue
				}
				techData.TechDetails[tech].Icon = snapshot.TechIcons[i]
				techData.TechDetails[tech].Website = snapshot.TechWebsites[i]
				techData.TechDetails[tech].Category = snapshot.TechCategories[i]
				hashes[entry.Hash(tech)] = struct{}{}
				techData.Technologies[tech] = append(techData.Technologies[tech], entry)
			}
		}
		lastIndex = lastID
	}

	data, err := json.Marshal(techData)
	if err != nil {
		logger.Error().Err(err).Msg("error during marshal")
		middleware.ReturnError(w, "internal error during processing", 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
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
			Filters: &am.FilterType{},
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
		OrgID:   orgID,
		GroupID: groupID,
		Filters: &am.FilterType{},
		Start:   0,
		Limit:   0,
	}

	afterRequest := values.Get(am.FilterWebAfterURLRequestTime)
	if afterRequest != "" {
		afterRequestTime, err := strconv.ParseInt(afterRequest, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebAfterURLRequestTime, afterRequestTime)
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

	if len(values["with_header"]) > 0 {
		filter.Filters.AddStrings(am.FilterWebHeaderNames, values["with_header"])
	}

	if len(values["without_header"]) > 0 {
		filter.Filters.AddStrings(am.FilterWebNotHeaderNames, values["without_header"])
	}

	if len(values["mime_type"]) > 0 {
		filter.Filters.AddStrings(am.FilterWebMimeType, values["mime_type"])
	}

	if values.Get(am.FilterWebLatestOnly) == "true" {
		filter.Filters.AddBool(am.FilterWebLatestOnly, true)
	}

	headerName := values.Get(am.FilterWebHeaderPairNames)
	headerValue := values.Get(am.FilterWebHeaderPairValues)
	if headerName != "" && headerValue != "" {
		filter.Filters.AddString(am.FilterWebHeaderPairNames, headerName)
		filter.Filters.AddString(am.FilterWebHeaderPairValues, headerValue)
	}

	responseURL := values.Get(am.FilterWebEqualsURL)
	if responseURL != "" {
		filter.Filters.AddString(am.FilterWebEqualsURL, responseURL)
	}

	ipAddress := values.Get(am.FilterWebEqualsIPAddress)
	if ipAddress != "" {
		filter.Filters.AddString(am.FilterWebEqualsIPAddress, ipAddress)
	}

	hostAddress := values.Get(am.FilterWebEqualsHostAddress)
	if hostAddress != "" {
		filter.Filters.AddString(am.FilterWebEqualsHostAddress, hostAddress)
	}

	endHostAddress := values.Get(am.FilterWebEndsHostAddress)
	if endHostAddress != "" {
		filter.Filters.AddString(am.FilterWebEndsHostAddress, endHostAddress)
	}

	startHostAddress := values.Get(am.FilterWebStartsHostAddress)
	if startHostAddress != "" {
		filter.Filters.AddString(am.FilterWebStartsHostAddress, startHostAddress)
	}

	loadIPAddress := values.Get("original_ip_address")
	if loadIPAddress != "" {
		filter.Filters.AddString(am.FilterWebEqualsLoadIPAddress, loadIPAddress)
	}

	loadHostAddress := values.Get("original_host_address")
	if loadHostAddress != "" {
		filter.Filters.AddString(am.FilterWebEqualsLoadHostAddress, loadHostAddress)
	}

	endLoadHostAddress := values.Get("ends_original_host_address")
	if endLoadHostAddress != "" {
		filter.Filters.AddString(am.FilterWebEndsLoadHostAddress, endLoadHostAddress)
	}

	startLoadHostAddress := values.Get("starts_original_host_address")
	if startLoadHostAddress != "" {
		filter.Filters.AddString(am.FilterWebStartsLoadHostAddress, startLoadHostAddress)
	}

	serverType := values.Get(am.FilterWebEqualsServerType)
	if serverType != "" {
		filter.Filters.AddString(am.FilterWebEqualsServerType, serverType)
	}

	urlRequestTime := values.Get(am.FilterWebEqualsURLRequestTime)
	if urlRequestTime != "" {
		urlRequestTimestamp, err := strconv.ParseInt(urlRequestTime, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebEqualsURLRequestTime, urlRequestTimestamp)
	}

	responseTime := values.Get(am.FilterWebEqualsResponseTime)
	if responseTime != "" {
		responseTimestamp, err := strconv.ParseInt(responseTime, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebEqualsResponseTime, responseTimestamp)
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
	log.Info().Msgf("Applying filter: %#v", filter)
	return filter, nil
}

func (h *WebHandlers) ParseCertificatesFilterQuery(values url.Values, orgID, groupID int) (*am.WebCertificateFilter, error) {
	var err error
	filter := &am.WebCertificateFilter{
		OrgID:   orgID,
		GroupID: groupID,
		Filters: &am.FilterType{},
		Start:   0,
		Limit:   0,
	}

	afterResponse := values.Get(am.FilterWebAfterResponseTime)
	if afterResponse != "" {
		afterResponseTime, err := strconv.ParseInt(afterResponse, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebAfterResponseTime, afterResponseTime)
	}

	beforeResponse := values.Get(am.FilterWebBeforeResponseTime)
	if beforeResponse != "" {
		beforeResponseTime, err := strconv.ParseInt(beforeResponse, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebBeforeResponseTime, beforeResponseTime)
	}

	afterValidTo := values.Get(am.FilterWebAfterValidTo)
	if afterValidTo != "" {
		validToValue, err := strconv.ParseInt(afterValidTo, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebAfterValidTo, validToValue)
	}

	beforeValidTo := values.Get(am.FilterWebBeforeValidTo)
	if beforeValidTo != "" {
		validToValue, err := strconv.ParseInt(beforeValidTo, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebBeforeValidTo, validToValue)
	}

	afterValidFrom := values.Get(am.FilterWebAfterValidFrom)
	if afterValidFrom != "" {
		validToValue, err := strconv.ParseInt(afterValidFrom, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebAfterValidFrom, validToValue)
	}

	beforeValidFrom := values.Get(am.FilterWebBeforeValidFrom)
	if beforeValidFrom != "" {
		validToValue, err := strconv.ParseInt(beforeValidFrom, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebBeforeValidFrom, validToValue)
	}

	hostAddress := values.Get(am.FilterWebEqualsHostAddress)
	if hostAddress != "" {
		filter.Filters.AddString(am.FilterWebEqualsHostAddress, hostAddress)
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

func (h *WebHandlers) ParseSnapshotsFilterQuery(values url.Values, orgID, groupID int, fromTime time.Time) (*am.WebSnapshotFilter, error) {
	var err error
	filter := &am.WebSnapshotFilter{
		OrgID:   orgID,
		GroupID: groupID,
		Filters: &am.FilterType{},
		Start:   0,
		Limit:   0,
	}

	afterResponse := values.Get(am.FilterWebAfterResponseTime)
	if afterResponse != "" {
		afterResponseTime, err := strconv.ParseInt(afterResponse, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterWebAfterResponseTime, afterResponseTime)
	}

	hostAddress := values.Get(am.FilterWebEqualsHostAddress)
	if hostAddress != "" {
		filter.Filters.AddString(am.FilterWebEqualsHostAddress, hostAddress)
	}

	dependentHostAddress := values.Get(am.FilterWebDependentHostAddress)
	if dependentHostAddress != "" {
		filter.Filters.AddString(am.FilterWebDependentHostAddress, dependentHostAddress)
		filter.Filters.AddInt64(am.FilterWebAfterURLRequestTime, fromTime.Add(time.Hour*(-24*7)).UnixNano())
	}

	techType := values.Get(am.FilterWebTechType)
	if techType != "" {
		filter.Filters.AddString(am.FilterWebTechType, techType)
	}

	techTypeVersion := values.Get(am.FilterWebTechTypeVersion)
	if techTypeVersion != "" {
		filter.Filters.AddString(am.FilterWebTechTypeVersion, techTypeVersion)
	}

	port := values.Get("port")
	if port != "" {
		portValue, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt32("port", int32(portValue))
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
