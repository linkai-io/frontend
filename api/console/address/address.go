package address

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/linkai-io/am/pkg/convert"
	"github.com/linkai-io/am/pkg/inputlist"
	"github.com/linkai-io/am/pkg/parsers"
	"github.com/rs/zerolog/log"

	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"

	"github.com/linkai-io/am/am"
)

type AddressResponse struct {
	Addrs     []*am.ScanGroupAddress `json:"addresses"`
	Status    string                 `json:"status"`
	LastIndex int64                  `json:"last_index"`
	Total     int                    `json:"total"`
}

type AddressStatsResponse struct {
	Stats  []*am.ScanGroupAddressStats `json:"stats"`
	Status string                      `json:"status"`
}

type HostlistResponse struct {
	Hosts    []*am.ScanGroupHostList `json:"hosts"`
	Status   string                  `json:"status"`
	LastHost string                  `json:"last_host"`
}

type AddressHandlers struct {
	addrClient       am.AddressService
	scanGroupClient  am.ScanGroupService
	orgClient        am.OrganizationService
	ContextExtractor middleware.UserContextExtractor
}

func New(addrClient am.AddressService, scanGroupClient am.ScanGroupService, orgClient am.OrganizationService) *AddressHandlers {
	return &AddressHandlers{
		addrClient:       addrClient,
		scanGroupClient:  scanGroupClient,
		orgClient:        orgClient,
		ContextExtractor: middleware.ExtractUserContext,
	}
}

func (h *AddressHandlers) OrgStats(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	log.Info().Msg("getting stats for org")
	oid, stats, err := h.addrClient.OrgStats(req.Context(), userContext)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get addresses")
		middleware.ReturnError(w, "failed to get addresses: "+err.Error(), 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(err).Msg("authorization failure")
		middleware.ReturnError(w, "failed to get addresses", 500)
		return
	}
	log.Info().Msgf("stats... %#v\n", stats)
	for i := 0; i < len(stats); i++ {
		log.Info().Msgf("%#v\n", stats[i])
	}
	response := &AddressStatsResponse{
		Status: "OK",
		Stats:  stats,
	}

	data, err := json.Marshal(response)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get marshal response")
		middleware.ReturnError(w, "failed return addresses", 500)
		return
	}

	fmt.Fprintf(w, string(data))
}

func (h *AddressHandlers) GetHostList(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	filter, err := h.ParseGetFilterQuery(req.URL.Query(), userContext.GetOrgID(), groupID)
	if err != nil {
		logger.Error().Err(err).Msg("failed parse url query parameters")
		middleware.ReturnError(w, "invalid parameters supplied", 401)
		return
	}

	oid, hosts, err := h.addrClient.GetHostList(req.Context(), userContext, filter)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get hosts")
		middleware.ReturnError(w, "failed to get hosts: "+err.Error(), 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(err).Msg("authorization failure")
		middleware.ReturnError(w, "failed to get hosts", 500)
		return
	}

	var lastHost string
	for _, host := range hosts {
		host.ETLD, err = parsers.GetETLD(host.HostAddress)
		if err != nil {
			logger.Warn().Err(err).Msg("failed parsing etld from host address")
			host.ETLD = host.HostAddress
		}
		lastHost = host.HostAddress
	}

	response := &HostlistResponse{
		Status:   "OK",
		LastHost: lastHost,
		Hosts:    hosts,
	}

	data, err := json.Marshal(response)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get marshal response")
		middleware.ReturnError(w, "failed return hostlist", 500)
		return
	}

	fmt.Fprintf(w, string(data))

}

func (h *AddressHandlers) GetAddresses(w http.ResponseWriter, req *http.Request) {
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	filter, err := h.ParseGetFilterQuery(req.URL.Query(), userContext.GetOrgID(), groupID)
	if err != nil {
		logger.Error().Err(err).Msg("failed parse url query parameters")
		middleware.ReturnError(w, "invalid parameters supplied: "+err.Error(), 401)
		return
	}
	logger.Info().Msgf("Getting address with filters: %#v", filter.Filters)
	oid, addrs, err := h.addrClient.Get(req.Context(), userContext, filter)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get addresses")
		middleware.ReturnError(w, "failed to get addresses: "+err.Error(), 500)
		return
	}

	var lastAddr int64
	for _, addr := range addrs {
		if addr.AddressID > lastAddr {
			lastAddr = addr.AddressID
		}
		if oid != addr.OrgID {
			logger.Error().Err(err).Msg("authorization failure")
			middleware.ReturnError(w, "failed to get addresses", 500)
			return
		}
	}

	oid, total, err := h.addrClient.Count(req.Context(), userContext, groupID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get address count")
		middleware.ReturnError(w, "failed to get address count: "+err.Error(), 500)
		return
	}

	response := &AddressResponse{
		Status:    "OK",
		LastIndex: lastAddr,
		Addrs:     addrs,
		Total:     total,
	}

	data, err := json.Marshal(response)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get marshal response")
		middleware.ReturnError(w, "failed return addresses", 500)
		return
	}

	fmt.Fprintf(w, string(data))
}

func (h *AddressHandlers) ParseGetFilterQuery(values url.Values, orgID, groupID int) (*am.ScanGroupAddressFilter, error) {
	var err error
	filter := &am.ScanGroupAddressFilter{
		OrgID:   orgID,
		GroupID: groupID,
		Start:   0,
		Limit:   0,
		Filters: &am.FilterType{},
	}
	log.Info().Msgf("parsing URL Filter: %#v\n", values)
	ignored := values.Get(am.FilterIgnored)
	if ignored == "true" {
		filter.Filters.AddBool(am.FilterIgnored, true)
	}

	notIgnored := values.Get("not_" + am.FilterIgnored)
	if notIgnored == "true" {
		filter.Filters.AddBool(am.FilterIgnored, false)
	}

	wildcard := values.Get(am.FilterWildcard)
	if wildcard == "true" {
		filter.Filters.AddBool(am.FilterWildcard, true)
	}

	notWildcard := values.Get("not_" + am.FilterWildcard)
	if notWildcard == "true" {
		filter.Filters.AddBool(am.FilterWildcard, false)
	}

	hosted := values.Get(am.FilterHosted)
	if hosted == "true" {
		filter.Filters.AddBool(am.FilterHosted, true)
	}

	notHosted := values.Get("not_" + am.FilterHosted)
	if notHosted == "false" {
		filter.Filters.AddBool(am.FilterHosted, false)
	}

	beforeScanned := values.Get(am.FilterBeforeScannedTime)
	if beforeScanned != "" {
		beforeScannedTime, err := strconv.ParseInt(beforeScanned, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterBeforeScannedTime, beforeScannedTime)
	}

	afterScanned := values.Get(am.FilterAfterScannedTime)
	if afterScanned != "" {
		afterScannedTime, err := strconv.ParseInt(afterScanned, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterAfterScannedTime, afterScannedTime)
	}

	beforeSeen := values.Get(am.FilterBeforeSeenTime)
	if beforeSeen != "" {
		beforeSeenTime, err := strconv.ParseInt(beforeSeen, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterBeforeSeenTime, beforeSeenTime)
	}

	afterSeen := values.Get(am.FilterAfterSeenTime)
	if afterSeen != "" {
		afterSeenTime, err := strconv.ParseInt(afterSeen, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterAfterSeenTime, afterSeenTime)
	}

	beforeDiscovered := values.Get(am.FilterBeforeDiscoveredTime)
	if beforeDiscovered != "" {
		beforeDiscoveredTime, err := strconv.ParseInt(beforeDiscovered, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterBeforeDiscoveredTime, beforeDiscoveredTime)
	}

	afterDiscovered := values.Get(am.FilterAfterDiscoveredTime)
	if afterDiscovered != "" {
		afterDiscoveredTime, err := strconv.ParseInt(afterDiscovered, 10, 64)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddInt64(am.FilterAfterDiscoveredTime, afterDiscoveredTime)
	}

	equalsConfidence := values.Get(am.FilterEqualsConfidence)
	if equalsConfidence != "" {
		equalsConfidenceValue, err := validateFloat(equalsConfidence, am.FilterEqualsConfidence, 0, 100)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddFloat32(am.FilterEqualsConfidence, float32(equalsConfidenceValue))
	}

	aboveConfidence := values.Get(am.FilterAboveConfidence)
	if aboveConfidence != "" {
		aboveConfidenceValue, err := validateFloat(aboveConfidence, am.FilterAboveConfidence, 0, 99)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddFloat32(am.FilterAboveConfidence, float32(aboveConfidenceValue))
	}

	belowConfidence := values.Get(am.FilterBelowConfidence)
	if belowConfidence != "" {
		belowConfidenceValue, err := validateFloat(belowConfidence, am.FilterBelowConfidence, 0, 100)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddFloat32(am.FilterBelowConfidence, float32(belowConfidenceValue))
	}

	equalsUserConfidence := values.Get(am.FilterEqualsUserConfidence)
	if equalsUserConfidence != "" {
		equalsUserConfidenceValue, err := validateFloat(equalsUserConfidence, am.FilterEqualsUserConfidence, 0, 100)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddFloat32(am.FilterEqualsUserConfidence, float32(equalsUserConfidenceValue))
	}

	aboveUserConfidence := values.Get(am.FilterAboveUserConfidence)
	if aboveUserConfidence != "" {
		aboveUserConfidenceValue, err := validateFloat(aboveUserConfidence, am.FilterAboveUserConfidence, 0, 99)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddFloat32(am.FilterAboveUserConfidence, float32(aboveUserConfidenceValue))
	}

	belowUserConfidence := values.Get(am.FilterBelowUserConfidence)
	if belowUserConfidence != "" {
		belowUserConfidenceValue, err := validateFloat(belowUserConfidence, am.FilterBelowUserConfidence, 0, 100)
		if err != nil {
			return nil, err
		}
		filter.Filters.AddFloat32(am.FilterBelowUserConfidence, float32(belowUserConfidenceValue))
	}

	if records, ok := values[am.FilterEqualsNSRecord+"[]"]; ok {
		for _, record := range records {
			recordValue, ok := am.NSRecords[record]
			if !ok {
				return nil, errors.New("invalid ns record name for " + am.FilterEqualsNSRecord + "[]")
			}
			filter.Filters.AddInt32(am.FilterEqualsNSRecord, int32(recordValue))
		}
	}

	record := values.Get(am.FilterEqualsNSRecord)
	if record != "" {
		recordValue, ok := am.NSRecords[record]
		if !ok {
			return nil, errors.New("invalid ns record name for " + am.FilterEqualsNSRecord)
		}
		filter.Filters.AddInt32(am.FilterEqualsNSRecord, int32(recordValue))
	}

	if notRecords, ok := values[am.FilterNotNSRecord+"[]"]; ok {
		for _, notRecord := range notRecords {
			recordValue, ok := am.NSRecords[notRecord]
			if !ok {
				return nil, errors.New("invalid ns record name for " + am.FilterNotNSRecord + "[]")
			}
			filter.Filters.AddInt32(am.FilterNotNSRecord, int32(recordValue))
		}
	}

	notRecord := values.Get(am.FilterNotNSRecord)
	if notRecord != "" {
		recordValue, ok := am.NSRecords[notRecord]
		if !ok {
			return nil, errors.New("invalid ns record name for " + am.FilterNotNSRecord)
		}
		filter.Filters.AddInt32(am.FilterNotNSRecord, int32(recordValue))
	}

	if ipAddresses, ok := values[am.FilterIPAddress+"[]"]; ok {
		for _, ipAddress := range ipAddresses {
			filter.Filters.AddString(am.FilterIPAddress, ipAddress)
		}
	}
	ipAddress := values.Get(am.FilterIPAddress)
	if ipAddress != "" {
		filter.Filters.AddString(am.FilterIPAddress, ipAddress)
	}

	if notIPAddresses, ok := values[am.FilterNotIPAddress+"[]"]; ok {
		for _, notIPAddress := range notIPAddresses {
			filter.Filters.AddString(am.FilterNotIPAddress, notIPAddress)
		}
	}
	notIPAddress := values.Get(am.FilterNotIPAddress)
	if notIPAddress != "" {
		filter.Filters.AddString(am.FilterNotIPAddress, notIPAddress)
	}

	if hostAddresses, ok := values[am.FilterHostAddress+"[]"]; ok {
		for _, hostAddress := range hostAddresses {
			filter.Filters.AddString(am.FilterHostAddress, hostAddress)
		}
	}
	hostAddress := values.Get(am.FilterHostAddress)
	if hostAddress != "" {
		filter.Filters.AddString(am.FilterHostAddress, hostAddress)
	}

	if notHostAddresses, ok := values[am.FilterNotHostAddress+"[]"]; ok {
		for _, notHostAddress := range notHostAddresses {
			filter.Filters.AddString(am.FilterNotHostAddress, notHostAddress)
		}
	}
	notHostAddress := values.Get(am.FilterNotHostAddress)
	if notHostAddress != "" {
		filter.Filters.AddString(am.FilterNotHostAddress, notHostAddress)
	}

	if endHostAddresses, ok := values[am.FilterEndsHostAddress+"[]"]; ok {
		for _, endHostAddress := range endHostAddresses {
			filter.Filters.AddString(am.FilterEndsHostAddress, endHostAddress)
		}
	}
	endHostAddress := values.Get(am.FilterEndsHostAddress)
	if endHostAddress != "" {
		filter.Filters.AddString(am.FilterEndsHostAddress, endHostAddress)
	}

	if notEndHostAddresses, ok := values[am.FilterNotEndsHostAddress+"[]"]; ok {
		for _, notEndHostAddress := range notEndHostAddresses {
			filter.Filters.AddString(am.FilterNotEndsHostAddress, notEndHostAddress)
		}
	}
	notEndHostAddress := values.Get(am.FilterNotEndsHostAddress)
	if notEndHostAddress != "" {
		filter.Filters.AddString(am.FilterNotEndsHostAddress, notEndHostAddress)
	}

	if startsHostAddresses, ok := values[am.FilterStartsHostAddress+"[]"]; ok {
		for _, startsHostAddress := range startsHostAddresses {
			filter.Filters.AddString(am.FilterStartsHostAddress, startsHostAddress)
		}
	}

	startsHostAddress := values.Get(am.FilterStartsHostAddress)
	if startsHostAddress != "" {
		filter.Filters.AddString(am.FilterStartsHostAddress, startsHostAddress)
	}

	if notStartsHostAddresses, ok := values[am.FilterNotStartsHostAddress+"[]"]; ok {
		for _, notStartsHostAddress := range notStartsHostAddresses {
			filter.Filters.AddString(am.FilterNotStartsHostAddress, notStartsHostAddress)
		}
	}

	notStartsHostAddress := values.Get(am.FilterNotStartsHostAddress)
	if notStartsHostAddress != "" {
		filter.Filters.AddString(am.FilterNotStartsHostAddress, notStartsHostAddress)
	}

	//FilterContainsHostAddress
	if containsHostAddresses, ok := values[am.FilterContainsHostAddress+"[]"]; ok {
		for _, containshostAddress := range containsHostAddresses {
			filter.Filters.AddString(am.FilterContainsHostAddress, containshostAddress)
		}
	}
	containsHostAddress := values.Get(am.FilterContainsHostAddress)
	if containsHostAddress != "" {
		filter.Filters.AddString(am.FilterContainsHostAddress, containsHostAddress)
	}

	if notContainsHostAddresses, ok := values[am.FilterNotContainsHostAddress+"[]"]; ok {
		for _, notContainsHostAddress := range notContainsHostAddresses {
			filter.Filters.AddString(am.FilterNotContainsHostAddress, notContainsHostAddress)
		}
	}
	notContainsHostAddress := values.Get(am.FilterNotContainsHostAddress)
	if notContainsHostAddress != "" {
		filter.Filters.AddString(am.FilterNotContainsHostAddress, notContainsHostAddress)
	}

	start := values.Get("start")
	if start == "" {
		filter.Start = 0
	} else {
		filter.Start, err = strconv.ParseInt(start, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	limit := values.Get("limit")
	if limit == "" {
		filter.Limit = 0
	} else {
		filter.Limit, err = strconv.Atoi(limit)
		if err != nil {
			return nil, err
		}
		if filter.Limit > 5000 {
			return nil, errors.New("limit max size exceeded (5000)")
		}
	}
	log.Info().Msgf("restricting results with filter %v %#v", filter, filter.Filters)
	return filter, nil
}

func validateFloat(in, field string, min, max float64) (float64, error) {
	inValue, err := strconv.ParseFloat(in, 32)
	if err != nil {
		return 0, err
	}
	if inValue > max {
		return 0, fmt.Errorf("value exceeds maximum of %f for %s", max, field)
	}
	if inValue < min {
		return 0, fmt.Errorf("value exceeds minimum of %f for %s", min, field)
	}
	return inValue, nil
}

type PutResponse struct {
	Msg          string                  `json:"msg"`
	Status       string                  `json:"status"`
	ParserErrors []*inputlist.ParseError `json:"errors,omitempty"`
	Count        int                     `json:"count,omitempty"`
}

func (h *AddressHandlers) PutAddresses(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	putResponse := &PutResponse{}

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	_, org, err := h.orgClient.GetByCID(req.Context(), userContext, userContext.GetOrgCID())
	if err != nil {
		logger.Warn().Err(err).Msg("failed to get org data")
		middleware.ReturnError(w, "failure to retrieve organization", 500)
		return
	}

	if org.LimitHostsReached {
		msg := fmt.Sprintf("number of hostnames exceeds the limit (%d) for your pricing plan", org.LimitHosts)
		middleware.ReturnError(w, msg, 400)
		return
	}

	groupID, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}
	logger.Info().Msg("processing list")
	defer req.Body.Close()

	addrs, parserErrors := inputlist.ParseList(req.Body, int(org.LimitHosts)) // 10000
	logger.Info().Int("addr_len", len(addrs)).Msg("parsed list")

	if len(addrs) > int(org.LimitHosts) {
		msg := fmt.Sprintf("hosts (%d) of this input list exceeded limit of %d for your pricing plan", len(addrs), org.LimitHosts)
		middleware.ReturnError(w, msg, 400)
		return
	}

	if len(addrs) == 0 {
		middleware.ReturnError(w, "no valid addresses supplied", 400)
		return
	}

	if len(parserErrors) != 0 {
		logger.Error().Int("GroupID", groupID).Msg("error processing input")
		putResponse.ParserErrors = parserErrors
		putResponse.Status = "error"
		data, err = json.Marshal(putResponse)
		if err != nil {
			logger.Error().Err(err).Int("GroupID", groupID).Msg("error processing input")
			middleware.ReturnError(w, "internal error", 500)
			return
		}
		w.WriteHeader(400)
		logger.Error().Msgf("%s", string(data))
		fmt.Fprint(w, string(data))
		return
	}

	tlds := make(map[string]struct{}, 0)
	for host := range addrs {
		etld, err := parsers.GetETLD(host)
		if err != nil {
			continue
		}
		tlds[etld] = struct{}{}
	}

	if len(tlds) > int(org.LimitTLD) {
		msg := fmt.Sprintf("top level domains (%d) of this input list exceeded limit of %d domains for your pricing plan", len(tlds), org.LimitTLD)
		middleware.ReturnError(w, msg, 400)
		return
	}

	sgAddrs := makeAddrs(addrs, userContext.GetOrgID(), userContext.GetUserID(), groupID)
	logger.Info().Int("sgaddr_len", len(sgAddrs)).Msg("created scangroup addresses")

	oid, count, err := h.addrClient.Update(req.Context(), userContext, sgAddrs)
	if err != nil {
		logger.Error().Err(err).Msg("failed to add addresses")
		middleware.ReturnError(w, "failed to add addresses to scangroup", 500)
		return
	}
	logger.Info().Int("count", count).Msg("got count from update")

	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Int("org_id", oid).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	putResponse.Count = count
	putResponse.Status = "OK"
	putResponse.Msg = "Upload Successful"

	data, err = json.Marshal(putResponse)
	if err != nil {
		logger.Error().Err(err).Msg("failed to marshal response")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprintf(w, string(data))
}

func (h *AddressHandlers) getSubscriptionDetails(userContext am.UserContext, org *am.Organization) (limitTLD int32, limitHosts int32) {
	subID := userContext.GetSubscriptionID()
	if org == nil {
		switch subID {
		case am.SubscriptionMonthlySmall:
			return 1, 25
		case am.SubscriptionMonthlyMedium:
			return 3, 260
		case am.SubscriptionEnterprise:
			return 200, 10000
		}
	}

	return org.LimitTLD, org.LimitHosts
}

func makeAddrs(in map[string]struct{}, orgID, userID, groupID int) map[string]*am.ScanGroupAddress {
	addrs := make(map[string]*am.ScanGroupAddress, len(in))
	i := 0
	for addr := range in {
		sgAddr := &am.ScanGroupAddress{
			OrgID:               orgID,
			GroupID:             groupID,
			DiscoveredBy:        "input_list",
			DiscoveryTime:       time.Now().UnixNano(),
			ConfidenceScore:     100.0,
			UserConfidenceScore: 0.0,
		}

		if inputlist.IsIP(addr) {
			sgAddr.IPAddress = addr
		} else {
			sgAddr.HostAddress = addr
		}
		sgAddr.AddressHash = convert.HashAddress(sgAddr.IPAddress, sgAddr.HostAddress)
		addrs[sgAddr.AddressHash] = sgAddr
		i++
	}
	return addrs
}

type countResponse struct {
	Status  string `json:"status"`
	GroupID int    `json:"group_id"`
	Count   int    `json:"count"`
}

func (h *AddressHandlers) GetGroupCount(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	oid, count, err := h.addrClient.Count(req.Context(), userContext, id)
	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	data, err = json.Marshal(&countResponse{Status: "OK", GroupID: id, Count: count})
	if err != nil {
		logger.Error().Err(err).Msg("error marshaling response")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

type deleteAddressRequest struct {
	AddressIDs []int64 `json:"address_ids"`
}

func (h *AddressHandlers) DeleteAddresses(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read body")
		middleware.ReturnError(w, "error reading address details", 400)
		return
	}
	defer req.Body.Close()

	addresses := &deleteAddressRequest{}
	if err := json.Unmarshal(body, addresses); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal addresses")
		middleware.ReturnError(w, "error reading addresses", 400)
		return
	}

	oid, err := h.addrClient.Delete(req.Context(), userContext, id, addresses.AddressIDs)
	if err != nil {
		logger.Error().Err(err).Msg("error deleting addresses")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Int("org_id", oid).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	middleware.ReturnSuccess(w, "addresses deleted", 200)
}

type ignoreAddressRequest struct {
	IgnoreValue bool    `json:"ignore_value"`
	AddressIDs  []int64 `json:"address_ids"`
}

func (h *AddressHandlers) IgnoreAddresses(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read body")
		middleware.ReturnError(w, "error reading address details", 400)
		return
	}
	defer req.Body.Close()

	addresses := &ignoreAddressRequest{}
	if err := json.Unmarshal(body, addresses); err != nil {
		logger.Error().Err(err).Msg("failed to read addresses")
		middleware.ReturnError(w, "error reading addresses", 400)
		return
	}

	oid, err := h.addrClient.Ignore(req.Context(), userContext, id, addresses.AddressIDs, addresses.IgnoreValue)
	if err != nil {
		logger.Error().Err(err).Msg("error ignoring addresses")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	if oid != userContext.GetOrgID() {
		logger.Error().Err(am.ErrOrgIDMismatch).Int("org_id", oid).Msg("authorization failure")
		middleware.ReturnError(w, "internal error", 500)
		return
	}

	middleware.ReturnSuccess(w, "addresses ignored", 200)
}

type exportAddressRequest struct {
	AllAddresses bool    `json:"all_addresses"`
	AddressIDs   []int64 `json:"address_ids,omitempty"`
}

func (h *AddressHandlers) ExportAddresses(w http.ResponseWriter, req *http.Request) {
	var err error
	var body []byte

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	body, err = ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read body")
		middleware.ReturnError(w, "error reading address details", 400)
		return
	}
	defer req.Body.Close()

	exportAddrs := &exportAddressRequest{}
	if err := json.Unmarshal(body, exportAddrs); err != nil {
		logger.Error().Err(err).Msg("failed to read addresses")
		middleware.ReturnError(w, "error reading addresses", 400)
		return
	}
	requestedAddrIDs := make(map[int64]struct{}, len(exportAddrs.AddressIDs))
	for _, addrID := range exportAddrs.AddressIDs {
		requestedAddrIDs[addrID] = struct{}{}
	}

	allAddresses := make([]*am.ScanGroupAddress, 0)

	var lastIndex int64
	for {
		filter := &am.ScanGroupAddressFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: id,
			Start:   lastIndex,
			Limit:   1000,
			Filters: &am.FilterType{},
		}
		oid, addrs, err := h.addrClient.Get(req.Context(), userContext, filter)
		if err != nil {
			logger.Error().Err(err).Msg("error deleting addresses")
			middleware.ReturnError(w, "internal error", 500)
			return
		}

		if len(addrs) == 0 {
			break
		}

		var lastAddr int64
		for _, addr := range addrs {
			if addr.AddressID > lastAddr {
				lastAddr = addr.AddressID
			}

			if exportAddrs.AllAddresses {
				allAddresses = append(allAddresses, addr)
			} else if _, ok := requestedAddrIDs[addr.AddressID]; ok {
				allAddresses = append(allAddresses, addr)
			}

			if oid != addr.OrgID {
				logger.Error().Err(err).Msg("authorization failure")
				middleware.ReturnError(w, "failed to get addresses", 500)
				return
			}
		}
		lastIndex = lastAddr
	}

	data, err := json.Marshal(allAddresses)
	if err != nil {
		logger.Error().Err(err).Msg("error during marshal")
		middleware.ReturnError(w, "internal error during processing", 500)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=addresses.%d.%d.json", id, time.Now().Unix()))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *AddressHandlers) ExportHostList(w http.ResponseWriter, req *http.Request) {

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}
	logger := middleware.UserContextLogger(userContext)

	id, err := groupIDFromRequest(req)
	if err != nil {
		middleware.ReturnError(w, "invalid scangroup id supplied", 401)
		return
	}

	req.Body.Close()

	allHosts := make([]*am.ScanGroupHostList, 0)

	var lastHost string
	for {
		filter := &am.ScanGroupAddressFilter{
			OrgID:   userContext.GetOrgID(),
			GroupID: id,
			Limit:   1000,
			Filters: &am.FilterType{},
		}
		filter.Filters.AddString("start_host", lastHost)
		oid, hosts, err := h.addrClient.GetHostList(req.Context(), userContext, filter)
		if err != nil {
			logger.Error().Err(err).Msg("error getting addresses")
			middleware.ReturnError(w, "internal error", 500)
			return
		}

		if len(hosts) == 0 {
			break
		}

		for _, host := range hosts {
			host.ETLD, err = parsers.GetETLD(host.HostAddress)
			if err != nil {
				logger.Warn().Err(err).Msg("failed parsing etld from host address")
				host.ETLD = host.HostAddress
			}

			allHosts = append(allHosts, host)

			if oid != host.OrgID {
				logger.Error().Err(err).Msg("authorization failure")
				middleware.ReturnError(w, "failed to get addresses", 500)
				return
			}
			lastHost = host.HostAddress
		}
	}

	data, err := json.Marshal(allHosts)
	if err != nil {
		logger.Error().Err(err).Msg("error during marshal")
		middleware.ReturnError(w, "internal error during processing", 500)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=hosts.%d.%d.json", id, time.Now().Unix()))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func groupIDFromRequest(req *http.Request) (int, error) {
	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	return id, err
}
