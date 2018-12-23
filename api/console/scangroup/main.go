package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/linkai-io/frontend/pkg/serializers"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
)

var scanGroupClient am.ScanGroupService
var env string
var region string

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "ScanGroup").Logger()
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")

	sec := secrets.NewSecretsCache(env, region)

	scanGroupClient = initializers.ScanGroupClient(sec)
}

func GetScanGroups(w http.ResponseWriter, req *http.Request) {
	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	oid, groups, err := scanGroupClient.Groups(req.Context(), userContext)
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

func GetScanGroup(w http.ResponseWriter, req *http.Request) {
	userContext, ok := middleware.ExtractUserContext(req.Context())
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

	oid, group, err := scanGroupClient.Get(req.Context(), userContext, groupID)
	if err != nil {
		middleware.ReturnError(w, "error listing groups", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
	}

	groupForUser := &serializers.ScanGroupForUser{group}

	data, _ := json.Marshal(groupForUser)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func GetScanGroupByName(w http.ResponseWriter, req *http.Request) {
	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "name")

	oid, group, err := scanGroupClient.GetByName(req.Context(), userContext, param)
	if err != nil {
		middleware.ReturnError(w, "error listing groups", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		log.Error().Err(am.ErrOrgIDMismatch).Int("OrgID", userContext.GetOrgID()).Int("UserID", userContext.GetUserID()).Str("TraceID", userContext.GetTraceID()).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
	}

	groupForUser := &serializers.ScanGroupForUser{group}

	data, _ := json.Marshal(groupForUser)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func CreateScanGroup(w http.ResponseWriter, req *http.Request) {

}

func UpdateScanGroup(w http.ResponseWriter, req *http.Request) {

}
func DeleteScanGroup(w http.ResponseWriter, req *http.Request) {

}

func UpdateScanGroupStatus(w http.ResponseWriter, req *http.Request) {

}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)

	r.Route("/scangroup", func(r chi.Router) {
		r.Get("/groups", GetScanGroups)
		r.Get("/id/{id}", GetScanGroup)
		r.Get("/name/{name}", GetScanGroupByName)
		r.Post("/id/{id}", CreateScanGroup)
		r.Patch("/id/{id}", UpdateScanGroup)
		r.Delete("/id/{id}", DeleteScanGroup)
		r.Patch("/id/{id}/status", UpdateScanGroupStatus)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
