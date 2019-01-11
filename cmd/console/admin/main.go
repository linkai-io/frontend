package main

import (
	"errors"
	"os"
	"time"

	"github.com/linkai-io/frontend/api/console/admin"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var orgClient am.OrganizationService
var userClient am.UserService
var provisioner provision.OrgProvisioner
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

	provisioner = provision.NewOrgProvision(env, region, userClient, orgClient)
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

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	healthHandlers := admin.NewHealthHandlers()
	provHandlers := admin.NewProvisionHandlers(orgClient, provisioner, roles)

	r.Route("/admin", func(admin chi.Router) {
		admin.Get("/health", healthHandlers.CheckHealth)
		admin.Route("/provision", func(prov chi.Router) {
			prov.Post("/org/{name}", provHandlers.CreateOrg)
			prov.Delete("/org/{name}", provHandlers.DeleteOrg)
			prov.Patch("/org/{name}", provHandlers.UpdateOrg)
			prov.Post("/user/{name}", provHandlers.CreateUser)
		})

	})
	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
