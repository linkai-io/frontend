package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog/log"
)

type ActivityHandlers struct {
	orgClient         am.OrganizationService
	scanGroupClient   am.ScanGroupService
	coordinatorClient am.CoordinatorService
	ContextExtractor  middleware.UserContextExtractor
	roles             map[string]string
}

func NewActivityHandlers(orgClient am.OrganizationService, scanGroupClient am.ScanGroupService, coordinatorClient am.CoordinatorService) *ActivityHandlers {
	return &ActivityHandlers{
		orgClient:         orgClient,
		scanGroupClient:   scanGroupClient,
		coordinatorClient: coordinatorClient,
		ContextExtractor:  middleware.ExtractUserContext,
	}
}

type OrgList struct {
	Orgs   []*am.Organization `json:"orgs"`
	Status string             `json:"status"`
}

func (h *ActivityHandlers) ListOrganizations(w http.ResponseWriter, req *http.Request) {
	var data []byte

	log.Info().Msg("list orgs called")

	adminContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	filter := &am.OrgFilter{
		Start:   0,
		Limit:   100,
		Filters: &am.FilterType{},
	}
	orgs, err := h.orgClient.List(req.Context(), adminContext, filter)
	if err != nil {
		log.Error().Err(err).Msg("failed to list organizations")
		middleware.ReturnError(w, "failed to list organizations: "+err.Error(), 500)
		return
	}
	o := &OrgList{
		Orgs:   orgs,
		Status: "ok",
	}
	data, _ = json.Marshal(o)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

type GroupList struct {
	Groups []*am.ScanGroup `json:"groups"`
	Status string          `json:"status"`
}

func (h *ActivityHandlers) ListGroups(w http.ResponseWriter, req *http.Request) {
	var data []byte

	log.Info().Msg("list groups called")

	adminContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	filter := &am.ScanGroupFilter{
		Filters: &am.FilterType{},
	}

	groups, err := h.scanGroupClient.AllGroups(req.Context(), adminContext, filter)
	if err != nil {
		log.Error().Err(err).Msg("failed to list groups")
		middleware.ReturnError(w, "failed to list group: "+err.Error(), 500)
		return
	}

	g := &GroupList{
		Groups: groups,
		Status: "ok",
	}
	data, _ = json.Marshal(g)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

type ActivityResponse struct {
	Groups []*am.ScanGroup        `json:"groups"`
	Stats  map[int]*am.GroupStats `json:"group_stats"`
}

func (h *ActivityHandlers) GroupActivity(w http.ResponseWriter, req *http.Request) {
	var data []byte

	log.Info().Msg("group activity called")

	adminContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	filter := &am.ScanGroupFilter{
		Filters: &am.FilterType{},
	}

	groups, err := h.scanGroupClient.AllGroups(req.Context(), adminContext, filter)
	if err != nil {
		log.Error().Err(err).Msg("failed to list groups for getting group activity")
		middleware.ReturnError(w, "failed to list group for getting group activity: "+err.Error(), 500)
		return
	}

	resp := &ActivityResponse{}
	resp.Groups = groups
	resp.Stats = make(map[int]*am.GroupStats)
	for _, group := range groups {

		proxyContext := &am.UserContextData{
			UserID:  group.CreatedByID,
			OrgID:   group.OrgID,
			TraceID: adminContext.GetTraceID(),
		}

		_, stats, err := h.scanGroupClient.GroupStats(req.Context(), proxyContext)
		if err != nil {
			log.Warn().Err(err).Msg("unable to get group stats for proxy org")
			continue
		}
		if _, ok := resp.Stats[group.GroupID]; !ok {
			resp.Stats[group.GroupID] = stats[group.GroupID]
		}
	}

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}
