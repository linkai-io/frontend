package main

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/rs/zerolog/log"
)

func testAddrClient() am.AddressService {
	addrClient := &mock.AddressService{}
	allAddresses := make(map[int64]*am.ScanGroupAddress)
	addrLock := &sync.RWMutex{}
	var addrID int64
	atomic.AddInt64(&addrID, 1)

	addrClient.OrgStatsFn = func(ctx context.Context, userContext am.UserContext) (int, []*am.ScanGroupAddressStats, error) {
		orgStats := make([]*am.ScanGroupAddressStats, 0)

		for i := 0; i < 2; i++ {
			discoTriHourly := &am.ScanGroupAggregates{}
			discoTriHourly.Time = make([]int64, 24)
			discoTriHourly.Count = make([]int32, 24)

			seenTriHourly := &am.ScanGroupAggregates{}
			seenTriHourly.Time = make([]int64, 24)
			seenTriHourly.Count = make([]int32, 24)

			scannedTriHourly := &am.ScanGroupAggregates{}
			scannedTriHourly.Time = make([]int64, 24)
			scannedTriHourly.Count = make([]int32, 24)

			for j := 0; j < 24; j++ {
				t := time.Now().Add(time.Hour * time.Duration(-3*j))
				discoTriHourly.Time[j] = t.UnixNano()
				discoTriHourly.Count[j] = int32(rand.Intn(15))
				log.Info().Msgf("%d %d", discoTriHourly.Time[j], discoTriHourly.Count[j])
				seenTriHourly.Time[j] = t.UnixNano()
				seenTriHourly.Count[j] = int32(rand.Intn(15))

				scannedTriHourly.Time[j] = t.UnixNano()
				scannedTriHourly.Count[j] = int32(rand.Intn(15))
			}

			orgStats = append(orgStats, &am.ScanGroupAddressStats{
				OrgID:   userContext.GetOrgID(),
				GroupID: i,
				DiscoveredBy: []string{
					am.DiscoveryNSInputList,
					am.DiscoveryBigDataCT,
					am.DiscoveryBruteMutator,
					am.DiscoveryBruteSubDomain,
				},
				DiscoveredByCount: []int32{
					10, 20, 5, 100,
				},
				Aggregates: map[string]*am.ScanGroupAggregates{
					"discovery_trihourly": discoTriHourly,
					"seen_trihourly":      seenTriHourly,
					"scanned_trihourly":   scannedTriHourly,
				},
				Total:          0,
				ConfidentTotal: int32(i),
			})
		}

		log.Info().Msgf("%#v\n", orgStats)

		return userContext.GetOrgID(), orgStats, nil
	}

	addrClient.GetHostListFn = func(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (int, []*am.ScanGroupHostList, error) {
		// fake host list
		hosts := make([]*am.ScanGroupHostList, 0)
		i := filter.Start
		if i > 1000 {
			return userContext.GetOrgID(), hosts, nil
		}
		for ; i < filter.Start+int64(100); i++ {
			host := &am.ScanGroupHostList{
				OrgID:       userContext.GetOrgID(),
				GroupID:     filter.GroupID,
				HostAddress: fmt.Sprintf("%d.example.com", i),
				AddressIDs:  []int64{int64(i * 10), int64(i*10 + 1)},
				IPAddresses: []string{fmt.Sprintf("192.168.1.%d", i), fmt.Sprintf("192.168.1.%d", i+1)},
				//Ports: &am.PortResults{}
			}
			hosts = append(hosts, host)
		}
		return userContext.GetOrgID(), hosts, nil
	}

	addrClient.GetFn = func(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (int, []*am.ScanGroupAddress, error) {
		addrLock.RLock()
		defer addrLock.RUnlock()
		addresses := make([]*am.ScanGroupAddress, 0)
		i := 0
		log.Info().Msgf("GETTING ADDRS: %#v", filter)
		sortedKeys := make([]int64, 0)

		for addrID, addr := range allAddresses {
			if filter.GroupID != addr.GroupID {
				continue
			}
			sortedKeys = append(sortedKeys, addrID)
		}
		sort.Slice(sortedKeys, func(i, j int) bool { return sortedKeys[i] < sortedKeys[j] })

		for _, key := range sortedKeys {
			addr := allAddresses[key]
			if filter.Limit < i {
				log.Info().Msgf("limit %d i %d", filter.Limit, i)
				break
			}

			if addr.AddressID > filter.Start && filter.Limit > i {
				log.Info().Msgf("adding addr %#v", addr)
				addresses = append(addresses, addr)
				i++
			}
		}
		log.Info().Int("length", len(addresses)).Msg("returning addresses")
		return userContext.GetOrgID(), addresses, nil
	}

	addrClient.CountFn = func(ctx context.Context, userContext am.UserContext, groupID int) (oid int, count int, err error) {
		addrLock.RLock()
		defer addrLock.RUnlock()
		i := 0
		for _, addr := range allAddresses {
			if addr.GroupID == groupID {
				i++
			}
		}
		return userContext.GetOrgID(), i, nil
	}

	addrClient.UpdateFn = func(ctx context.Context, userContext am.UserContext, addresses map[string]*am.ScanGroupAddress) (oid int, count int, err error) {
		addrLock.Lock()
		defer addrLock.Unlock()
		for _, addr := range addresses {
			log.Info().Msgf("adding %#v", addr)
			if addr.AddressID == 0 {
				newID := atomic.AddInt64(&addrID, 1)
				addr.AddressID = newID
				allAddresses[newID] = addr
			} else {
				allAddresses[addr.AddressID] = addr
			}
		}
		log.Info().Int("count", len(addresses)).Msg("updated addresses")
		return userContext.GetOrgID(), len(addresses), nil
	}

	addrClient.DeleteFn = func(ctx context.Context, userContext am.UserContext, groupID int, addressIDs []int64) (oid int, err error) {
		addrLock.Lock()
		defer addrLock.Unlock()
		for _, id := range addressIDs {
			delete(allAddresses, id)
		}
		return userContext.GetOrgID(), nil
	}

	addrClient.IgnoreFn = func(ctx context.Context, userContext am.UserContext, groupID int, addressIDs []int64, ignoreValue bool) (oid int, err error) {
		addrLock.Lock()
		defer addrLock.Unlock()
		for _, id := range addressIDs {
			allAddresses[id].Ignored = ignoreValue
		}
		return userContext.GetOrgID(), nil
	}
	return addrClient
}
