package address

import (
	"context"
	"io"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/convert"
	"github.com/linkai-io/am/pkg/retrier"
	service "github.com/linkai-io/am/protocservices/address"
	"github.com/linkai-io/am/protocservices/prototypes"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
)

type Client struct {
	client         service.AddressClient
	conn           *grpc.ClientConn
	defaultTimeout time.Duration
}

func New() *Client {
	return &Client{defaultTimeout: (time.Second * 10)}
}

func (c *Client) Init(config []byte) error {
	conn, err := grpc.DialContext(context.Background(), "srv://consul/"+am.AddressServiceKey, grpc.WithInsecure(), grpc.WithBalancerName(roundrobin.Name))
	if err != nil {
		return err
	}

	c.conn = conn
	c.client = service.NewAddressClient(conn)
	return nil
}

func (c *Client) SetTimeout(timeout time.Duration) {
	c.defaultTimeout = timeout
}

func (c *Client) Get(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (oid int, addresses []*am.ScanGroupAddress, err error) {
	var resp service.Address_GetClient
	oid = userContext.GetOrgID()

	in := &service.AddressesRequest{
		UserContext: convert.DomainToUserContext(userContext),
		Filter:      convert.DomainToAddressFilter(filter),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.Get(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to get addresses from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, nil, err
	}

	addresses = make([]*am.ScanGroupAddress, 0)
	for {
		addr, err := resp.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return 0, nil, err
		}
		// empty address
		if addr.GetOrgID() == 0 {
			continue
		}
		addresses = append(addresses, convert.AddressToDomain(addr.Addresses))
		if addr.GetOrgID() != int32(oid) {
			return 0, nil, am.ErrOrgIDMismatch
		}
	}
	return oid, addresses, nil
}

func (c *Client) GetHostList(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (oid int, hosts []*am.ScanGroupHostList, err error) {
	var resp service.Address_GetHostListClient
	oid = userContext.GetOrgID()

	in := &service.HostListRequest{
		UserContext: convert.DomainToUserContext(userContext),
		Filter:      convert.DomainToAddressFilter(filter),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.GetHostList(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to get hostlist from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, nil, err
	}

	hosts = make([]*am.ScanGroupHostList, 0)
	for {
		host, err := resp.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return 0, nil, err
		}
		// empty address
		if host.GetOrgID() == 0 {
			continue
		}
		hosts = append(hosts, convert.HostListToDomain(host.HostList))
		if host.GetOrgID() != int32(oid) {
			return 0, nil, am.ErrOrgIDMismatch
		}
	}
	return oid, hosts, nil
}

func (c *Client) OrgStats(ctx context.Context, userContext am.UserContext) (oid int, orgStats []*am.ScanGroupAddressStats, err error) {
	var resp *service.OrgStatsResponse
	oid = userContext.GetOrgID()

	in := &service.OrgStatsRequest{
		UserContext: convert.DomainToUserContext(userContext),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.OrgStats(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to get address org stats from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, nil, err
	}
	return int(resp.GetOrgID()), convert.ScanGroupsAddressStatsToDomain(resp.GetGroupStats()), nil
}

func (c *Client) GroupStats(ctx context.Context, userContext am.UserContext, groupID int) (oid int, groupStats *am.ScanGroupAddressStats, err error) {
	var resp *service.GroupStatsResponse
	oid = userContext.GetOrgID()

	in := &service.GroupStatsRequest{
		UserContext: convert.DomainToUserContext(userContext),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.GroupStats(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to get address group stats from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, nil, err
	}
	return int(resp.GetOrgID()), convert.ScanGroupAddressStatsToDomain(resp.GetGroupStats()), nil
}

func (c *Client) Update(ctx context.Context, userContext am.UserContext, addresses map[string]*am.ScanGroupAddress) (oid int, count int, err error) {
	var resp *service.UpdateAddressesResponse

	protoAddresses := make(map[string]*prototypes.AddressData, len(addresses))

	for key, val := range addresses {
		protoAddresses[key] = convert.DomainToAddress(val)
	}

	in := &service.UpdateAddressRequest{
		UserContext: convert.DomainToUserContext(userContext),
		Address:     protoAddresses,
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.Update(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to update addresses from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, 0, err
	}

	return int(resp.GetOrgID()), int(resp.GetCount()), nil
}

func (c *Client) UpdateHostPorts(ctx context.Context, userContext am.UserContext, address *am.ScanGroupAddress, portResults *am.PortResults) (oid int, err error) {
	var resp *service.UpdateHostPortsResponse

	in := &service.UpdateHostPortsRequest{
		UserContext: convert.DomainToUserContext(userContext),
		Address:     convert.DomainToAddress(address),
		PortResult:  convert.DomainToPortResults(portResults),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.UpdateHostPorts(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to update hostports from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, err
	}

	return int(resp.GetOrgID()), nil
}

func (c *Client) Count(ctx context.Context, userContext am.UserContext, groupID int) (oid int, count int, err error) {
	var resp *service.CountAddressesResponse

	in := &service.CountAddressesRequest{
		UserContext: convert.DomainToUserContext(userContext),
		GroupID:     int32(groupID),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.Count(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to count addresses from client")

	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, 0, err
	}

	return int(resp.GetOrgID()), int(resp.Count), nil
}

func (c *Client) Delete(ctx context.Context, userContext am.UserContext, groupID int, addressIDs []int64) (oid int, err error) {
	var resp *service.DeleteAddressesResponse

	in := &service.DeleteAddressesRequest{
		UserContext: convert.DomainToUserContext(userContext),
		GroupID:     int32(groupID),
		AddressIDs:  addressIDs,
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.Delete(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to delete addresses from client")

	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, err
	}

	return int(resp.GetOrgID()), nil
}

func (c *Client) Ignore(ctx context.Context, userContext am.UserContext, groupID int, addressIDs []int64, ignoreValue bool) (oid int, err error) {
	var resp *service.IgnoreAddressesResponse

	in := &service.IgnoreAddressesRequest{
		UserContext: convert.DomainToUserContext(userContext),
		GroupID:     int32(groupID),
		AddressIDs:  addressIDs,
		IgnoreValue: ignoreValue,
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.Ignore(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to ignore addresses from client")

	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, err
	}

	return int(resp.GetOrgID()), nil
}

func (c *Client) Archive(ctx context.Context, userContext am.UserContext, group *am.ScanGroup, archiveTime time.Time) (oid int, count int, err error) {
	var resp *service.AddressesArchivedResponse
	oid = userContext.GetOrgID()

	in := &service.ArchiveAddressesRequest{
		UserContext: convert.DomainToUserContext(userContext),
		ScanGroup:   convert.DomainToScanGroup(group),
		ArchiveTime: archiveTime.UnixNano(),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.Archive(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to get address archive from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, 0, err
	}
	return int(resp.GetOrgID()), int(resp.Count), nil
}

// GetPorts returns ports that match the filter from address service
func (c *Client) GetPorts(ctx context.Context, userContext am.UserContext, filter *am.ScanGroupAddressFilter) (oid int, portResults []*am.PortResults, err error) {
	var resp service.Address_GetPortsClient
	oid = userContext.GetOrgID()

	in := &service.GetPortsRequest{
		UserContext: convert.DomainToUserContext(userContext),
		Filter:      convert.DomainToAddressFilter(filter),
	}

	ctxDeadline, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()

	err = retrier.RetryIfNot(func() error {
		var retryErr error

		resp, retryErr = c.client.GetPorts(ctxDeadline, in)
		return errors.Wrap(retryErr, "unable to get portResults from client")
	}, "rpc error: code = Unavailable desc")

	if err != nil {
		return 0, nil, err
	}

	portResults = make([]*am.PortResults, 0)
	for {
		port, err := resp.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return 0, nil, err
		}
		// empty address
		if port.GetOrgID() == 0 {
			continue
		}
		portResults = append(portResults, convert.PortResultsToDomain(port.PortResults))
		if port.GetOrgID() != int32(oid) {
			return 0, nil, am.ErrOrgIDMismatch
		}
	}
	return oid, portResults, nil
}
