package initializers

import (
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/clients/user"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/rs/zerolog/log"
)

func OrgClient(sec *secrets.SecretsCache) am.OrganizationService {
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	orgClient := organization.New()
	if err := orgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	log.Info().Str("load_balancer", lb).Msg("orgClient initialized with lb")
	return orgClient
}

func UserClient(sec *secrets.SecretsCache) am.UserService {
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	userClient := user.New()
	if err := userClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	log.Info().Str("load_balancer", lb).Msg("orgClient initialized with lb")
	return userClient
}
