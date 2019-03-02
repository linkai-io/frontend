package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
	"github.com/rs/zerolog/log"
)

func testScanGroupClient() am.ScanGroupService {
	var newID int32
	groupLock := &sync.RWMutex{}

	groups := make(map[int]*am.ScanGroup)

	scanGroupClient := &mock.ScanGroupService{}
	scanGroupClient.GetFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, *am.ScanGroup, error) {
		groupLock.RLock()
		defer groupLock.RUnlock()

		if sg, ok := groups[groupID]; ok {
			return userContext.GetOrgID(), sg, nil
		}
		return userContext.GetOrgID(), nil, am.ErrScanGroupNotExists
	}

	scanGroupClient.GetByNameFn = func(ctx context.Context, userContext am.UserContext, groupName string) (int, *am.ScanGroup, error) {
		groupLock.RLock()
		defer groupLock.RUnlock()

		for _, g := range groups {
			if g.GroupName == groupName {
				return userContext.GetOrgID(), g, nil
			}
		}

		return userContext.GetOrgID(), nil, am.ErrScanGroupNotExists
	}

	scanGroupClient.GroupsFn = func(ctx context.Context, userContext am.UserContext) (int, []*am.ScanGroup, error) {
		groupLock.RLock()
		defer groupLock.RUnlock()
		allGroups := make([]*am.ScanGroup, 0)
		for _, g := range groups {
			if g.Deleted {
				continue
			}
			allGroups = append(allGroups, g)
		}
		return userContext.GetOrgID(), allGroups, nil
	}

	scanGroupClient.CreateFn = func(ctx context.Context, userContext am.UserContext, newGroup *am.ScanGroup) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Str("group", g.GroupName).Str("new", newGroup.GroupName)
			if g.GroupName == newGroup.GroupName {
				return userContext.GetOrgID(), 0, errors.New("group name exists")
			}
		}
		gid := atomic.AddInt32(&newID, 1)
		newGroup.GroupID = int(gid)
		groups[int(gid)] = newGroup
		log.Info().Int("len", len(groups)).Msg("created new group")
		return userContext.GetOrgID(), int(gid), nil
	}

	scanGroupClient.UpdateFn = func(ctx context.Context, userContext am.UserContext, updatedGroup *am.ScanGroup) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Str("group", g.GroupName).Str("new", updatedGroup.GroupName)
			if g.GroupID == updatedGroup.GroupID {
				g = updatedGroup
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}

	scanGroupClient.PauseFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Int("group_id", g.GroupID).Int("requested_gid", groupID)
			if g.GroupID == groupID {
				g.Paused = true
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}

	scanGroupClient.ResumeFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Int("group_id", g.GroupID).Int("requested_gid", groupID)
			if g.GroupID == groupID {
				g.Paused = false
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}

	scanGroupClient.DeleteFn = func(ctx context.Context, userContext am.UserContext, groupID int) (int, int, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		for _, g := range groups {
			log.Info().Int("group_id", g.GroupID).Int("requested_gid", groupID)
			if g.GroupID == groupID {
				g.Deleted = true
				g.GroupName = fmt.Sprintf("%s%d", g.GroupName, time.Now().UnixNano())
				return userContext.GetOrgID(), g.GroupID, nil
			}
		}
		return userContext.GetOrgID(), 0, am.ErrScanGroupNotExists
	}

	scanGroupClient.GroupStatsFn = func(ctx context.Context, userContext am.UserContext) (int, map[int]*am.GroupStats, error) {
		groupLock.Lock()
		defer groupLock.Unlock()
		stats := make(map[int]*am.GroupStats, len(groups))
		for i, g := range groups {
			stats[g.GroupID] = &am.GroupStats{
				OrgID:           userContext.GetOrgID(),
				GroupID:         g.GroupID,
				ActiveAddresses: 10,
				BatchSize:       1000,
				LastUpdated:     time.Now().Add(-1 * time.Minute).UnixNano(),
				BatchStart:      time.Now().Add(-10 * time.Minute).UnixNano(),
				BatchEnd:        time.Now().Add(-30 * time.Second).UnixNano(),
			}
			if i > 1 {
				stats[g.GroupID].BatchEnd = 0
			}
		}
		return userContext.GetOrgID(), stats, nil
	}
	return scanGroupClient
}
