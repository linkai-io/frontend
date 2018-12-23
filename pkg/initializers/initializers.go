package initializers

import (
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/clients/scangroup"
	"github.com/linkai-io/am/clients/user"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/rs/zerolog/log"
)

// OrgClient return a connection to the organization service
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

// UserClient return a connection to the user service
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

// ScanGroupClient return a connection to the scan group service
func ScanGroupClient(sec *secrets.SecretsCache) am.ScanGroupService {
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	scanGroupClient := scangroup.New()
	if err := scanGroupClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	log.Info().Str("load_balancer", lb).Msg("orgClient initialized with lb")
	return scanGroupClient
}
