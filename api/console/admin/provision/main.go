package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
)

var orgClient am.OrganizationService
var userClient am.UserService
var provisioner *provision.OrgProvisioner
var roles map[string]string

func init() {
	var err error

	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Provisioner").Logger()
	env := os.Getenv("APP_ENV")
	region := os.Getenv("APP_REGION")
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	roles, err = orgRoles()
	if err != nil {
		log.Fatal().Err(err).Msg("error initializing roles")
	}

	orgClient = initializers.OrgClient()
	userClient = initializers.UserClient()

	provisioner = provision.NewOrgProvisioner(env, region, userClient, orgClient)
}

func orgRoles() (map[string]string, error) {
	roleMap := make(map[string]string, 7)
	for _, roleName := range []string{"authenticated", "unauthenticated", "owner", "admin", "auditor", "editor", "reviewer"} {
		roleMap[roleName] = os.Getenv(roleName)
		if roleMap[roleName] == "" {
			log.Error().Str("roleName", roleName).Msg("had empty value")
			return nil, errors.New("invalid value passed into org role environment var")
		}
	}
	return roleMap, nil
}

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

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	r.Route("/admin", func(admin chi.Router) {
		admin.Route("/provision", func(prov chi.Router) {
			prov.Post("/org/{name}", CreateOrg)
			prov.Delete("/org/{name}", DeleteOrg)
			prov.Patch("/org/{name}", UpdateOrg)
			prov.Post("/user/{name}", CreateUser)
		})
	})
	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
