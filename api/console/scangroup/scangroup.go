package scangroup

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/linkai-io/frontend/pkg/serializers"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
)

// TODO: should probably make this better/find a good example.
func ValidateSubDomain(fl validator.FieldLevel) bool {
	str := fl.Field().String()
	return !strings.ContainsAny(str, " ~`!@#$%^&*()=+[]{};\"'|<>,.?\r\n\x00\x01\x02\x03\x03\x04\x05\x06\x07\x08\t")
}

type NewScanGroup struct {
	GroupName          string   `json:"group_name" validate:"required,gte=1,lte=128,excludesall=/"`
	CustomSubNames     []string `json:"custom_sub_names" validate:"omitempty,max=100,dive,gte=1,lte=128,subdomain"`
	CustomPorts        []int32  `json:"custom_ports" validate:"omitempty,max=10,dive,gte=1,lte=65535"`
	ConcurrentRequests int32    `json:"concurrent_requests" validate:"required,gte=1,lte=25"`
}

type ScanGroupEnv struct {
	Env    string
	Region string
}

type ScanGroupHandlers struct {
	validate         *validator.Validate
	env              *ScanGroupEnv
	scanGroupClient  am.ScanGroupService
	userClient       am.UserService
	ContextExtractor middleware.UserContextExtractor
}

func New(scanGroupClient am.ScanGroupService, env *ScanGroupEnv) *ScanGroupHandlers {
	validate := validator.New()
	validate.RegisterValidation("subdomain", ValidateSubDomain)
	return &ScanGroupHandlers{
		scanGroupClient:  scanGroupClient,
		env:              env,
		ContextExtractor: middleware.ExtractUserContext,
		validate:         validate,
	}
}

func (h *ScanGroupHandlers) GetScanGroups(w http.ResponseWriter, req *http.Request) {
	log.Info().Msg("getting scan groups for user")
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	oid, groups, err := h.scanGroupClient.Groups(req.Context(), userContext)
	if err != nil {
		middleware.ReturnError(w, "error listing groups", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
	}

	groupsForUser := make([]*serializers.ScanGroupForUser, len(groups))
	for i, g := range groups {
		groupsForUser[i] = &serializers.ScanGroupForUser{g}
	}

	data, _ := json.Marshal(groupsForUser)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *ScanGroupHandlers) GetScanGroupByID(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "id")
	groupID, err := strconv.Atoi(param)
	if err != nil {
		middleware.ReturnError(w, "invalid parameter", 403)
		return
	}

	oid, group, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting group", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	groupForUser := &serializers.ScanGroupForUser{group}

	data, _ := json.Marshal(groupForUser)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *ScanGroupHandlers) GetScanGroupByName(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "name")

	oid, group, err := h.scanGroupClient.GetByName(req.Context(), userContext, param)
	if err != nil {
		middleware.ReturnError(w, "error listing groups", 400)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	groupForUser := &serializers.ScanGroupForUser{group}

	data, _ := json.Marshal(groupForUser)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

type groupCreated struct {
	Status           string `json:"status"`
	GroupID          int    `json:"group_id"`
	UploadAddressURI string `json:"upload_address_uri"`
}

func (h *ScanGroupHandlers) CreateScanGroup(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte
	var gid int

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "name")
	if strings.Contains(param, "/") {
		middleware.ReturnError(w, "'/' is not allowed in the group name", 401)
		return
	}

	oid, exists, _ := h.scanGroupClient.GetByName(req.Context(), userContext, param)
	if exists != nil {
		middleware.ReturnError(w, "group name already exists", 400)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		middleware.ReturnError(w, "error reading scangroup from body", 400)
		return
	}
	defer req.Body.Close()

	groupDetails := &NewScanGroup{}
	if err := json.Unmarshal(body, groupDetails); err != nil {
		middleware.ReturnError(w, "error reading scangroup", 400)
		return
	}

	if err := h.validate.Struct(groupDetails); err != nil {
		log.Error().Err(err).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("invalid data passed")
		middleware.ReturnError(w, err.Error(), 401) // TODO: don't expose internal errors
		return
	}

	group := &am.ScanGroup{}
	group.OrgID = userContext.GetOrgID()
	group.CreatedBy = userContext.GetUserCID() // replaced with user email
	group.CreatedByID = userContext.GetUserID()
	group.ModifiedBy = userContext.GetUserCID() // replaced with user email
	group.ModifiedByID = userContext.GetUserID()
	group.OriginalInputS3URL = "s3://empty"
	group.Paused = true
	group.ModuleConfigurations = &am.ModuleConfiguration{
		NSModule: &am.NSModuleConfig{
			RequestsPerSecond: groupDetails.ConcurrentRequests,
		},
		BruteModule: &am.BruteModuleConfig{
			CustomSubNames:    groupDetails.CustomSubNames,
			RequestsPerSecond: groupDetails.ConcurrentRequests,
			MaxDepth:          2,
		},
		PortModule: &am.PortModuleConfig{
			RequestsPerSecond: groupDetails.ConcurrentRequests,
			CustomPorts:       groupDetails.CustomPorts,
		},
		WebModule: &am.WebModuleConfig{
			TakeScreenShots:       true,
			RequestsPerSecond:     groupDetails.ConcurrentRequests,
			MaxLinks:              10,
			ExtractJS:             true,
			FingerprintFrameworks: true,
		},
		KeywordModule: &am.KeywordModuleConfig{
			Keywords: []string{""},
		},
	}

	oid, gid, err = h.scanGroupClient.Create(req.Context(), userContext, group)
	if err != nil {
		log.Error().Err(err).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("error creating scangroup")
		middleware.ReturnError(w, "error creating scangroup", 400)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	environment := h.env.Env
	if h.env.Env == "prod" {
		environment = ""
	}

	created := &groupCreated{
		Status:           "OK",
		GroupID:          gid,
		UploadAddressURI: fmt.Sprintf("%s/address/%d/initial", environment, gid),
	}

	data, err := json.Marshal(created)
	if err != nil {
		middleware.ReturnError(w, "failed to create response", 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *ScanGroupHandlers) UpdateScanGroup(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "id")
	groupID, err := strconv.Atoi(param)
	if err != nil {
		middleware.ReturnError(w, "invalid parameter", 403)
		return
	}

	oid, original, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting original group", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		middleware.ReturnError(w, "error reading scangroup from body", 400)
		return
	}
	defer req.Body.Close()

	group := &am.ScanGroup{}
	if err := json.Unmarshal(body, group); err != nil {
		middleware.ReturnError(w, "error reading scangroup", 400)
		return
	}

	if strings.Contains(group.GroupName, "/") {
		middleware.ReturnError(w, "'/' is not allowed in the group name", 401)
		return
	}

	original.GroupName = group.GroupName
	original.ModifiedBy = userContext.GetUserCID() // replaced with user email
	original.ModifiedByID = userContext.GetUserID()
	original.ModuleConfigurations = group.ModuleConfigurations

	_, _, err = h.scanGroupClient.Update(req.Context(), userContext, original)
	if err != nil {
		middleware.ReturnError(w, "error updating scangroup", 400)
		return
	}

	middleware.ReturnSuccess(w, "group updated", 200)
}

func (h *ScanGroupHandlers) DeleteScanGroup(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "id")
	groupID, err := strconv.Atoi(param)
	if err != nil {
		middleware.ReturnError(w, "invalid parameter", 403)
		return
	}

	oid, group, err := h.scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error getting group", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	_, _, err = h.scanGroupClient.Delete(req.Context(), userContext, group.GroupID)
	if err != nil {
		log.Error().Err(err).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("deletion failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	middleware.ReturnSuccess(w, "OK", 200)
}

type groupStatus struct {
	Status string `json:"status"`
}

func (h *ScanGroupHandlers) UpdateScanGroupStatus(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "name")

	oid, group, err := h.scanGroupClient.GetByName(req.Context(), userContext, param)
	if err != nil {
		middleware.ReturnError(w, "failure retrieving group", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		middleware.ReturnError(w, "error reading scangroup from body", 400)
		return
	}
	defer req.Body.Close()

	status := &groupStatus{}
	if err := json.Unmarshal(body, status); err != nil {
		middleware.ReturnError(w, "error reading status", 400)
		return
	}

	if status.Status == "pause" {
		_, _, err = h.scanGroupClient.Pause(req.Context(), userContext, group.GroupID)
	} else if status.Status == "resume" {
		_, _, err = h.scanGroupClient.Resume(req.Context(), userContext, group.GroupID)
	} else {
		middleware.ReturnError(w, "unknown status supplied must be pause or resume", 400)
		return
	}

	if err != nil {
		log.Error().Err(err).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("deletion failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	middleware.ReturnSuccess(w, "OK", 200)
}
