package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/awg"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"go4.org/netipx"
)

// Mirrors device.HeaderCipherNonceSize in amneziawg-go/v3: the header cipher
// takes its nonce out of the S1-S4 padding. //H awg3
const awgHeaderProtectionMinPadding = 12

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register(registry, constant.TypeAwg, NewEndpoint)
}

type Endpoint struct {
	*awg.Device
	endpoint.Adapter
	ctx       context.Context
	options   option.AwgEndpointOptions
	address   []netip.Prefix
	router    adapter.Router
	logger    log.ContextLogger
	dnsRouter adapter.DNSRouter
}

const (
	awgMaxJunkPacketCount = 512
	awgMaxJunkPacketSize  = 4096
	awgMaxHandshakePad    = 4096
	awgMaxTransportPad    = 1024
)

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = 1408
	}
	if err := validateObfuscationOptions(options); err != nil {
		return nil, err
	}

	options.UDPFragmentDefault = true
	// Check if any peer has a domain address
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

	// Create peer resolver function for domain endpoints.
	// Always use system resolver for peer endpoints because:
	// 1. VPN server must be resolved before VPN tunnel is established
	// 2. dnsRouter may not be fully initialized at this stage
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

	// Pass a nil resolver so a domain peer endpoint is NOT resolved here (at
	// service-creation, before the Android VpnService/socket-protect exists — that
	// crashes cold-cache clients). It is resolved and applied in Start()/PostStart().
	ipc, err := genIpcConfig(options, nil)
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

	return &Endpoint{
		Device:    dev,
		Adapter:   endpoint.NewAdapterWithDialerOptions("awg", tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:       ctx,
		options:   options,
		address:   options.Address,
		router:    router,
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
	}, nil
}

// Start delegates lifecycle to the embedded WireGuard device, then — at PostStart,
// once the Android VpnService/socket-protect is available — resolves any domain peer
// endpoints (preferring IPv6, since our DS-Lite server has no usable inbound IPv4 for
// the awg port) and applies them via Device.IpcUpdate. Deferring the resolution here
// (instead of at NewEndpoint) is what avoids the "no VpnService for socket protect"
// crash on cold-cache clients while keeping the peer as an auto-following FQDN.
func (e *Endpoint) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if err := e.Device.Start(stage); err != nil {
		return err
	}
	if stage != adapter.StartStatePostStart {
		return nil
	}
	for _, peer := range e.options.Peers {
		if peer.Address == "" || peer.Port == 0 {
			continue
		}
		if M.ParseAddr(peer.Address).IsValid() {
			continue // literal IP: already configured at device start
		}
		addr, err := resolvePeerPreferIPv6(e.ctx, peer.Address)
		if err != nil {
			e.logger.Warn("awg: deferred resolve of peer ", peer.Address, " failed: ", err)
			continue
		}
		pkBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			continue
		}
		ipc := "public_key=" + hex.EncodeToString(pkBytes) +
			"\nupdate_only=true\nendpoint=" + formatAWGEndpoint(addr.String(), peer.Port) + "\n"
		if err := e.Device.IpcUpdate(ipc); err != nil {
			e.logger.Warn("awg: apply resolved peer endpoint failed: ", err)
			continue
		}
		e.logger.Info("awg: peer ", peer.Address, " -> ", addr.String(), " (resolved post-start)")
	}
	return nil
}

// resolvePeerPreferIPv6 resolves a peer FQDN preferring IPv6 (AAAA), falling back to
// IPv4. Safe to call at PostStart: the VpnService is up, so the resolver's sockets are
// protected. On our DS-Lite deployment IPv6 is the reachable path for the awg endpoint.
func resolvePeerPreferIPv6(ctx context.Context, domain string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", domain)
	if err != nil || len(addrs) == 0 {
		addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip4", domain)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, E.New("could not resolve peer: ", domain)
	}
	return addrs[0], nil
}

func resolveClientBindSinglePeerEndpoint(opts option.AwgEndpointOptions, resolvePeer func(domain string) (netip.Addr, error)) (netip.AddrPort, error) {
	if opts.Detour == "" {
		return netip.AddrPort{}, nil
	}
	return resolveSinglePeerEndpoint(opts, resolvePeer)
}

func resolveSinglePeerEndpoint(opts option.AwgEndpointOptions, resolvePeer func(domain string) (netip.Addr, error)) (netip.AddrPort, error) {
	if len(opts.Peers) != 1 {
		return netip.AddrPort{}, nil
	}
	peer := opts.Peers[0]
	if peer.Port == 0 || peer.Address == "" {
		return netip.AddrPort{}, nil
	}
	if addr := M.ParseAddr(peer.Address); addr.IsValid() {
		return netip.AddrPortFrom(addr, peer.Port), nil
	}
	if resolvePeer == nil {
		return netip.AddrPort{}, E.New("single peer client bind requires a resolvable peer endpoint")
	}
	resolvedAddr, err := resolvePeer(peer.Address)
	if err != nil {
		return netip.AddrPort{}, E.Cause(err, "resolve client bind peer endpoint ", peer.Address)
	}
	return netip.AddrPortFrom(resolvedAddr, peer.Port), nil
}

func resolveReservedForPeers(opts option.AwgEndpointOptions, resolvePeer func(domain string) (netip.Addr, error)) ([3]uint8, map[netip.AddrPort][3]uint8, error) {
	var reserved [3]uint8
	reservedForEndpoint := make(map[netip.AddrPort][3]uint8)
	for index, peer := range opts.Peers {
		if len(peer.Reserved) == 0 {
			continue
		}
		if len(peer.Reserved) != 3 {
			return [3]uint8{}, nil, E.New("invalid reserved value for peer ", index, ", required 3 bytes, got ", len(peer.Reserved))
		}
		var peerReserved [3]uint8
		copy(peerReserved[:], peer.Reserved)
		if len(opts.Peers) == 1 {
			reserved = peerReserved
		}
		if peer.Port == 0 || peer.Address == "" {
			continue
		}
		if addr := M.ParseAddr(peer.Address); addr.IsValid() {
			reservedForEndpoint[netip.AddrPortFrom(addr, peer.Port)] = peerReserved
			continue
		}
		if resolvePeer == nil {
			return [3]uint8{}, nil, E.New("peer reserved requires a resolvable peer endpoint: ", peer.Address)
		}
		resolvedAddr, err := resolvePeer(peer.Address)
		if err != nil {
			return [3]uint8{}, nil, E.Cause(err, "resolve peer endpoint for reserved ", peer.Address)
		}
		reservedForEndpoint[netip.AddrPortFrom(resolvedAddr, peer.Port)] = peerReserved
	}
	return reserved, reservedForEndpoint, nil
}

func validateObfuscationOptions(opts option.AwgEndpointOptions) error {
	if opts.Jc < 0 {
		return E.New("jc must be non-negative")
	}
	if opts.Jc > awgMaxJunkPacketCount {
		return E.New("jc must be at most ", awgMaxJunkPacketCount)
	}
	if opts.Jmin < 0 {
		return E.New("jmin must be non-negative")
	}
	if opts.Jmax < 0 {
		return E.New("jmax must be non-negative")
	}
	if opts.Jc > 0 && (opts.Jmin == 0 || opts.Jmax == 0) {
		return E.New("jmin and jmax are required when jc is set")
	}
	if opts.Jmin > 0 || opts.Jmax > 0 {
		if opts.Jmin == 0 || opts.Jmax == 0 {
			return E.New("jmin and jmax must be set together")
		}
		if opts.Jmin > opts.Jmax {
			return E.New("jmin must be less than or equal to jmax")
		}
		if opts.Jmax > awgMaxJunkPacketSize {
			return E.New("jmax must be at most ", awgMaxJunkPacketSize)
		}
	}
	if err := validatePaddingOption("s1", opts.S1, awgMaxHandshakePad); err != nil {
		return err
	}
	if err := validatePaddingOption("s2", opts.S2, awgMaxHandshakePad); err != nil {
		return err
	}
	if err := validatePaddingOption("s3", opts.S3, awgMaxHandshakePad); err != nil {
		return err
	}
	if err := validatePaddingOption("s4", opts.S4, awgMaxTransportPad); err != nil {
		return err
	}
	return nil
}

func validatePaddingOption(name string, value int, maxValue int) error {
	if value < 0 {
		return E.New(name, " must be non-negative")
	}
	if value > maxValue {
		return E.New(name, " must be at most ", maxValue)
	}
	return nil
}

func genIpcConfig(opts option.AwgEndpointOptions, resolvePeer func(domain string) (netip.Addr, error)) (string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
	if err != nil {
		return "", err
	}
	s := "private_key=" + hex.EncodeToString(privateKeyBytes)
	if opts.ListenPort != 0 {
		s += "\nlisten_port=" + format.ToString(opts.ListenPort)
	}
	if opts.Jc != 0 {
		s += "\njc=" + format.ToString(opts.Jc)
	}
	if opts.Jmin != 0 {
		s += "\njmin=" + format.ToString(opts.Jmin)
	}
	if opts.Jmax != 0 {
		s += "\njmax=" + format.ToString(opts.Jmax)
	}
	if opts.S1 != 0 {
		s += "\ns1=" + format.ToString(opts.S1)
	}
	if opts.S2 != 0 {
		s += "\ns2=" + format.ToString(opts.S2)
	}
	if opts.S3 != 0 {
		s += "\ns3=" + format.ToString(opts.S3)
	}
	if opts.S4 != 0 {
		s += "\ns4=" + format.ToString(opts.S4)
	}
	if opts.H1 != "" {
		s += "\nh1=" + opts.H1
	}
	if opts.H2 != "" {
		s += "\nh2=" + opts.H2
	}
	if opts.H3 != "" {
		s += "\nh3=" + opts.H3
	}
	if opts.H4 != "" {
		s += "\nh4=" + opts.H4
	}
	if opts.I1 != "" {
		s += "\ni1=" + opts.I1
	}
	if opts.I2 != "" {
		s += "\ni2=" + opts.I2
	}
	if opts.I3 != "" {
		s += "\ni3=" + opts.I3
	}
	if opts.I4 != "" {
		s += "\ni4=" + opts.I4
	}
	if opts.I5 != "" {
		s += "\ni5=" + opts.I5
	}
	// AWG 3.x. The UAPI takes the header protection key as hex, while the
	// Amnezia .conf spells it base64 — same split as private_key above. //H awg3
	if opts.HeaderProtectionKey != "" {
		// Header protection draws its per-packet nonce from the S1-S4 crypto
		// padding, so anything shorter than the ChaCha20 nonce silently breaks
		// the handshake instead of erroring out. Fail loudly here.
		for _, sv := range [][2]any{
			{"s1", opts.S1}, {"s2", opts.S2}, {"s3", opts.S3}, {"s4", opts.S4},
		} {
			if sv[1].(int) < awgHeaderProtectionMinPadding {
				return "", E.New("awg: header_protection_key requires ", sv[0], " >= ", awgHeaderProtectionMinPadding, ", got ", sv[1])
			}
		}
		headerKeyBytes, err := base64.StdEncoding.DecodeString(opts.HeaderProtectionKey)
		if err != nil {
			return "", err
		}
		s += "\nheader_protection_key=" + hex.EncodeToString(headerKeyBytes)
	}
	for _, kv := range [][2]string{
		{"content_padding_addition", opts.ContentPaddingAddition},
		{"rekey_after_time", opts.RekeyAfterTime},
		{"rekey_timeout", opts.RekeyTimeout},
		{"reject_after_time", opts.RejectAfterTime},
		{"keepalive_timeout", opts.KeepaliveTimeout},
		{"max_handshake_attempts", opts.MaxHandshakeAttempts},
	} {
		if kv[1] != "" {
			s += "\n" + kv[0] + "=" + kv[1]
		}
	}
	if opts.RandomTrailers {
		s += "\nrandom_trailers=true"
	}
	if opts.DisableCookies {
		s += "\ndisable_cookies=true"
	}

	for _, peer := range opts.Peers {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			return "", err
		}
		s += "\npublic_key=" + hex.EncodeToString(publicKeyBytes)
		if peer.PresharedKey != "" {
			presharedKeyBytes, err := base64.StdEncoding.DecodeString(peer.PresharedKey)
			if err != nil {
				return "", err
			}
			s += "\npreshared_key=" + hex.EncodeToString(presharedKeyBytes)
		}
		if peer.Address != "" && peer.Port != 0 {
			if addr := M.ParseAddr(peer.Address); addr.IsValid() {
				s += "\nendpoint=" + formatAWGEndpoint(peer.Address, peer.Port)
			} else if resolvePeer != nil {
				resolvedAddr, resolveErr := resolvePeer(peer.Address)
				if resolveErr != nil {
					return "", E.Cause(resolveErr, "resolve peer endpoint ", peer.Address)
				}
				s += "\nendpoint=" + formatAWGEndpoint(resolvedAddr.String(), peer.Port)
			}
			// domain peer with a nil resolver → endpoint DEFERRED: the awg endpoint
			// (endpoint.go Start/PostStart) resolves it after the VpnService/socket-protect
			// is up and applies it via Device.IpcUpdate. Resolving here (at NewEndpoint /
			// "create service") crashes cold-cache Android: "no VpnService for socket protect".
		}
		if peer.PersistentKeepaliveInterval != 0 {
			s += "\npersistent_keepalive_interval=" + format.ToString(peer.PersistentKeepaliveInterval)
		}
		for _, allowedIp := range peer.AllowedIPs {
			s += "\nallowed_ip=" + allowedIp.String()
		}
	}
	return s, nil
}

func formatAWGEndpoint(host string, port uint16) string {
	unwrappedHost := host
	if len(unwrappedHost) >= 2 && unwrappedHost[0] == '[' && unwrappedHost[len(unwrappedHost)-1] == ']' {
		unwrappedHost = unwrappedHost[1 : len(unwrappedHost)-1]
	}
	if addr, err := netip.ParseAddr(unwrappedHost); err == nil {
		return netip.AddrPortFrom(addr, port).String()
	}
	return net.JoinHostPort(unwrappedHost, strconv.Itoa(int(port)))
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	metadata.Destination = destination
	for _, addr := range e.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	e.logger.InfoContext(ctx, "inbound packet connection from ", source)
	e.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		e.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, e.Device, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.Device.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, e.Device, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, nil
	}
	return e.Device.ListenPacket(ctx, destination)
}

func (w *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Source = source
	for _, addr := range w.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	w.logger.InfoContext(ctx, "inbound connection from ", source)
	w.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	w.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
