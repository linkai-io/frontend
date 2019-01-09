package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// inputs from env / ssm
var (
	env          string
	region       string
	systemOrgID  int
	systemUserID int
)

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Provisioner").Logger()
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata
}

func create(ctx context.Context, provisioner *provision.OrgProvisioner, orgData *am.Organization, roles map[string]string, password string) error {
	log.Info().Msg("create called")

	if password == "" {
		return errors.New("password was empty")
	}

	userContext := &am.UserContextData{
		OrgID:  systemOrgID,
		UserID: systemUserID,
	}

	log.Info().Int("org_id", systemOrgID).Int("user_id", systemUserID).Str("org_name", orgData.OrgName).Msg("provisioning support organization")
	userPoolID, identityPoolID, err := provisioner.AddSupportOrganization(ctx, userContext, orgData, roles, password)

	log.Info().Str("UserPoolId", userPoolID).Str("IdentityPoolId", identityPoolID).Int("org_id", systemOrgID).Int("user_id", systemUserID).Str("org_name", orgData.OrgName).Msg("provisioning support organization complete")
	return err
}

func delete(ctx context.Context, provisioner *provision.OrgProvisioner, orgData *am.Organization, roles map[string]string, password string) error {
	userContext := &am.UserContextData{
		OrgID:  systemOrgID,
		UserID: systemUserID,
	}

	userPoolID, identityPoolID, err := provisioner.DeleteSupportOrganization(ctx, userContext, orgData.OrgName)
	if err != nil {
		log.Error().Err(err).Msg("failed to delete support org")
		return err
	}
	log.Info().Str("UserPoolId", userPoolID).Str("IdentityPoolId", identityPoolID).Msg("deleted support organization")
	return nil
}

func main() {
	var err error
	org := &am.Organization{}

	log.Info().Str("env", env).Str("region", region).Msg("provisioning initializing for stack")

	sec := secrets.NewSecretsCache(env, region)

	if systemOrgID, err = sec.SystemOrgID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system org id")
	}

	if systemUserID, err = sec.SystemUserID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system user id")
	}

	supportPassword, err := sec.GetSecureString(fmt.Sprintf("/am/%s/frontend/support/pwd", env))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get support password")
	}

	task := os.Getenv("task")
	if task == "" {
		task = "CREATE"
	}

	org.OrgName = os.Getenv("orgname")
	if org.OrgName == "" {
		log.Fatal().Err(err).Msg("orgname empty")
	}

	org.FirstName = os.Getenv("firstname")
	if org.FirstName == "" {
		log.Fatal().Err(err).Msg("firstname empty")
	}

	org.LastName = os.Getenv("lastname")
	if org.LastName == "" {
		log.Fatal().Err(err).Msg("lastname empty")
	}

	org.OwnerEmail = os.Getenv("email")
	if org.OwnerEmail == "" {
		log.Fatal().Err(err).Msg("email empty")
	}

	roles := make(map[string]string, 0)
	for _, role := range []string{"unauthenticated", "authenticated", "owner", "admin", "reviewer"} {
		v := os.Getenv(role)
		if v == "" {
			log.Fatal().Err(err).Str("role_name", role).Msg("was empty")
		}
		roles[role] = v
	}

	orgClient := initializers.OrgClient()
	userClient := initializers.UserClient()

	provisioner := provision.NewOrgProvisioner(env, region, userClient, orgClient)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	switch task {
	case "DELETE":
		err = delete(timeoutCtx, provisioner, org, roles, supportPassword)
	default:
		err = create(timeoutCtx, provisioner, org, roles, supportPassword)
	}

	if err != nil {
		log.Error().Err(err).Msg("failed to provision/deprovision org")
		return
	}

	log.Info().Msg("provisioner task run successfully.")
}
