package main

import (
	"errors"
	"os"
	"time"

	"github.com/linkai-io/am/pkg/secrets"

	"github.com/linkai-io/frontend/api/console/admin"

	"github.com/wirepair/gateway"
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
var scanGroupClient am.ScanGroupService
var coordinatorClient am.CoordinatorService
var provisioner provision.OrgProvisioner
var secret *secrets.SecretsCache

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
	scanGroupClient = initializers.ScanGroupClient()
	coordinatorClient = initializers.CoordinatorClient()
	secret = secrets.NewSecretsCache(env, region)
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
	systemOrgID, err := secret.SystemOrgID()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get system org id")
	}
	systemUserID, err := secret.SystemUserID()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get system user id")
	}
	healthHandlers := admin.NewHealthHandlers()
	provHandlers := admin.NewProvisionHandlers(orgClient, provisioner, roles)
	actHandlers := admin.NewActivityHandlers(orgClient, scanGroupClient, coordinatorClient, &am.UserContextData{
		OrgID:  systemOrgID,
		UserID: systemUserID,
	})

	r.Route("/admin", func(admin chi.Router) {
		admin.Get("/health", healthHandlers.CheckHealth)

		admin.Route("/provision", func(prov chi.Router) {
			prov.Post("/org/{name}", provHandlers.CreateOrg)
			prov.Delete("/org/{name}", provHandlers.DeleteOrg)
			prov.Patch("/org/{name}", provHandlers.UpdateOrg)
			prov.Post("/user/{name}", provHandlers.CreateUser)
		})

		admin.Route("/activity", func(act chi.Router) {
			act.Patch("/reset/groups", actHandlers.ResetGroup)
			act.Get("/orgs", actHandlers.ListOrganizations)
			act.Get("/groups", actHandlers.ListGroups)
			act.Get("/groupstatus", actHandlers.GroupActivity)
		})
	})

	err = gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
