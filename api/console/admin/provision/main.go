package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
)

var orgClient am.OrganizationService
var provisioner *provision.OrgProvisioner
var roles map[string]string

func init() {
	var err error

	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Provisioner").Logger()
	env := os.Getenv("APP_ENV")
	region := os.Getenv("APP_REGION")
	roles, err = orgRoles()
	if err != nil {
		log.Fatal().Err(err).Msg("error initializing roles")
	}

	sec := secrets.NewSecretsCache(env, region)
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	orgClient := initializers.OrgClient(lb)
	userClient := initializers.UserClient(lb)

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

func UpdateOrg(w http.ResponseWriter, req *http.Request) {

}
func CreateUser(w http.ResponseWriter, req *http.Request) {
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)

	r.Route("/provision", func(r chi.Router) {
		r.Post("/org/{name}", CreateOrg)
		r.Patch("/org/{name}", UpdateOrg)
		r.Post("/user/{name}", CreateUser)

	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
