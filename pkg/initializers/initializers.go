package initializers

import (
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/address"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/clients/scangroup"
	"github.com/linkai-io/am/clients/user"
	"github.com/rs/zerolog/log"
)

// OrgClient return a connection to the organization service
func OrgClient(loadBalancerAddr string) am.OrganizationService {
	orgClient := organization.New()
	if err := orgClient.Init([]byte(loadBalancerAddr)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	log.Info().Str("load_balancer", loadBalancerAddr).Msg("orgClient initialized with lb")
	return orgClient
}

// UserClient return a connection to the user service
func UserClient(loadBalancerAddr string) am.UserService {
	userClient := user.New()
	if err := userClient.Init([]byte(loadBalancerAddr)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	log.Info().Str("load_balancer", loadBalancerAddr).Msg("userClient initialized with lb")
	return userClient
}

// ScanGroupClient return a connection to the scan group service
func ScanGroupClient(loadBalancerAddr string) am.ScanGroupService {
	scanGroupClient := scangroup.New()
	if err := scanGroupClient.Init([]byte(loadBalancerAddr)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	log.Info().Str("load_balancer", loadBalancerAddr).Msg("scanGroupClient initialized with lb")
	return scanGroupClient
}

// AddressClient return a connection to the scan group service
func AddressClient(loadBalancerAddr string) am.AddressService {
	addrClient := address.New()
	if err := addrClient.Init([]byte(loadBalancerAddr)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	log.Info().Str("load_balancer", loadBalancerAddr).Msg("addrClient initialized with lb")
	return addrClient
}
