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

type AddressHandlers struct {
	addrClient       am.AddressService
	scanGroupClient  am.ScanGroupService
	ContextExtractor middleware.UserContextExtractor
}

func New(addrClient am.AddressService, scanGroupClient am.ScanGroupService) *AddressHandlers {
	return &AddressHandlers{
		addrClient:       addrClient,
		scanGroupClient:  scanGroupClient,
		ContextExtractor: middleware.ExtractUserContext,
	}
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
		middleware.ReturnError(w, "invalid parameters supplied", 401)
		return
	}

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
		Status:    "ok",
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
		OrgID:               orgID,
		GroupID:             groupID,
		WithIgnored:         false,
		IgnoredValue:        false,
		WithLastScannedTime: false,
		SinceScannedTime:    0,
		WithLastSeenTime:    false,
		SinceSeenTime:       0,
		Start:               0,
		Limit:               0,
	}

	ignored := values.Get("ignored")
	if ignored == "true" {
		filter.WithIgnored = true
		filter.IgnoredValue = true
	} else if ignored == "false" {
		filter.WithIgnored = true
		filter.IgnoredValue = false
	}

	sinceScanned := values.Get("since_scanned")
	if sinceScanned != "" {
		filter.WithLastScannedTime = true
		filter.SinceScannedTime, err = strconv.ParseInt(sinceScanned, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	sinceSeen := values.Get("since_seen")
	if sinceSeen != "" {
		filter.WithLastSeenTime = true
		filter.SinceSeenTime, err = strconv.ParseInt(sinceSeen, 10, 64)
		if err != nil {
			return nil, err
		}
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
		if filter.Limit > 1000 {
			return nil, errors.New("limit max size exceeded (1000)")
		}
	}
	return filter, nil
}

type PutResponse struct {
	Msg          string                  `json:"msg"`
	Status       string                  `json:"status"`
	ParserErrors []*inputlist.ParseError `json:"errors,omitempty"`
	Count        int                     `json:"count,omitempty"`
}

func (h *AddressHandlers) PutInitialAddresses(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	putResponse := &PutResponse{}

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
	logger.Info().Msg("processing list")
	defer req.Body.Close()

	addrs, parserErrors := inputlist.ParseList(req.Body, 100000)
	logger.Info().Int("addr_len", len(addrs)).Msg("parsed list")
	if len(parserErrors) != 0 {
		logger.Error().Int("GroupID", groupID).Msg("error processing input")
		putResponse.ParserErrors = parserErrors
		putResponse.Status = "NG"
		data, err = json.Marshal(putResponse)
		if err != nil {
			logger.Error().Err(err).Int("GroupID", groupID).Msg("error processing input")
			middleware.ReturnError(w, "internal error", 500)
			return
		}
		w.WriteHeader(400)
		fmt.Fprint(w, string(data))
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

func groupIDFromRequest(req *http.Request) (int, error) {
	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	return id, err
}
