package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/awg"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"go4.org/netipx"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AwgEndpointOptions](registry, constant.TypeAwg, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	device    *awg.Device
	logger    log.ContextLogger
	dnsRouter adapter.DNSRouter
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Outbound, error) {
	if options.MTU == 0 {
		options.MTU = 1408
	}
	if err := validateObfuscationOptions(options); err != nil {
		return nil, err
	}
	options.UDPFragmentDefault = true

	remoteIsDomain := common.Any(options.Peers, func(peer option.AwgPeerOptions) bool {
		return !M.ParseAddr(peer.Address).IsValid()
	})
	dial, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   remoteIsDomain,
		ResolverOnDetour: true,
		DirectOutbound:   true,
	})
	if err != nil {
		return nil, err
	}

	var allowedPrefixBuilder netipx.IPSetBuilder
	var excludedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
		if addr, err := netip.ParseAddr(peer.Address); err == nil {
			excludedPrefixBuilder.Add(addr)
		}
	}
	allowedIps, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	excludedIps, err := excludedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}

	var resolvePeer func(domain string) (netip.Addr, error)
	if remoteIsDomain {
		resolvePeer = func(domain string) (netip.Addr, error) {
			addrs, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip4", domain)
			if lookupErr != nil || len(addrs) == 0 {
				addrs, lookupErr = net.DefaultResolver.LookupNetIP(ctx, "ip6", domain)
			}

			if lookupErr != nil {
				return netip.Addr{}, lookupErr
			}

			if len(addrs) == 0 {
				return netip.Addr{}, fmt.Errorf("could not resolve peer: %s", domain)
			}

			return addrs[0], nil
		}
	}
	singlePeerEndpoint, err := resolveClientBindSinglePeerEndpoint(options, resolvePeer)
	if err != nil {
		return nil, err
	}
	clientBindReserved, reservedForEndpoint, err := resolveReservedForPeers(options, resolvePeer)
	if err != nil {
		return nil, err
	}

	ipc, err := genIpcConfig(options, resolvePeer)
	if err != nil {
		return nil, err
	}

	logger.Debug("AWG IPC config:\n", ipc)

	dev, err := awg.NewDevice(ctx, logger, dial, ipc, awg.DeviceOpts{
		UseIntegratedTun:    options.UseIntegratedTun,
		PeerEndpoint:        singlePeerEndpoint,
		Reserved:            clientBindReserved,
		ReservedForEndpoint: reservedForEndpoint,
		Address:             options.Address,
		AllowedIps:          allowedIps.Prefixes(),
		ExcludedIps:         excludedIps.Prefixes(),
		MTU:                 options.MTU,
	})
	if err != nil {
		return nil, err
	}

	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(constant.TypeAwg, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		device:    dev,
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
	}, nil
}

func (o *Outbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	return o.device.Start(stage)
}

func (o *Outbound) Close() error {
	return o.device.Close()
}

func (o *Outbound) InterfaceUpdated(_ context.Context) {
	o.device.InterfaceUpdated()
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, o.device, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return o.device.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, o.device, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, err
	}
	return o.device.ListenPacket(ctx, destination)
}
