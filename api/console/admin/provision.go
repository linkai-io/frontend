package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog/log"
)

func CreateOrg(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte
	orgDetails := &provision.OrgDetails{}

	log.Info().Msg("create org called")

	userContext, ok := middleware.ExtractUserContext(req.Context())
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

	if err := json.Unmarshal(data, orgDetails); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}

	org, err := orgDetails.ToOrganization()
	if err != nil {
		log.Error().Err(err).Msg("validation failed for provision data")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}

	if _, err := provisioner.Add(req.Context(), userContext, org, roles); err != nil {
		log.Error().Err(err).Msg("provisioner error")
		middleware.ReturnError(w, "error provisioning organization", 500)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func DeleteOrg(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	log.Info().Msg("delete org called")

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	name := chi.URLParam(req, "name")
	if name == "" || name == "linkai-support" || name == "linkai-system" {
		middleware.ReturnError(w, "invalid name supplied", 401)
		return
	}

	oid, org, err := orgClient.Get(req.Context(), userContext, name)
	if err != nil {
		log.Error().Err(err).Msg("failed to get org by name")
		middleware.ReturnError(w, "internal org lookup failure", 500)
		return
	}

	if _, err := orgClient.Delete(req.Context(), userContext, oid); err != nil {
		log.Error().Err(err).Msg("failed to delete organization")
		middleware.ReturnError(w, "failed to delete organization, inspect the logs", 500)
		return
	}

	if err := provisioner.Delete(req.Context(), org); err != nil {
		middleware.ReturnError(w, "failed to delete organization user and identity pools", 500)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func UpdateOrg(w http.ResponseWriter, req *http.Request) {

}
func CreateUser(w http.ResponseWriter, req *http.Request) {
}
