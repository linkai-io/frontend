package initializers

import (
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/address"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/clients/scangroup"
	"github.com/linkai-io/am/clients/user"
	"github.com/rs/zerolog/log"
)

// OrgClient return a connection to the organization service
func OrgClient() am.OrganizationService {
	orgClient := organization.New()
	orgClient.SetTimeout(time.Second * 15)
	if err := orgClient.Init(nil); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
	return orgClient
}

// UserClient return a connection to the user service
func UserClient() am.UserService {
	userClient := user.New()
	userClient.SetTimeout(time.Second * 15)
	if err := userClient.Init(nil); err != nil {
		log.Fatal().Err(err).Msg("error initializing user client")
	}
	return userClient
}

// ScanGroupClient return a connection to the scan group service
func ScanGroupClient() am.ScanGroupService {
	scanGroupClient := scangroup.New()
	scanGroupClient.SetTimeout(time.Second * 15)
	if err := scanGroupClient.Init(nil); err != nil {
		log.Fatal().Err(err).Msg("error initializing scangroup client")
	}
	return scanGroupClient
}

// AddressClient return a connection to the scan group service
func AddressClient() am.AddressService {
	addrClient := address.New()
	addrClient.SetTimeout(time.Second * 15)
	if err := addrClient.Init(nil); err != nil {
		log.Fatal().Err(err).Msg("error initializing address client")
	}
	return addrClient
}