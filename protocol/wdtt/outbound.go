package wdtt

// Native WG-over-VK (WDTT) client outbound. Mirrors the awg outbound but the
// WireGuard peer endpoint is the in-process VK-TURN bridge (127.0.0.1:<port>):
//
//	sing-box WG (netstack) -> 127.0.0.1:localPort -> [wdtt bridge: VK-TURN/WRAP/RTP/DTLS]
//	  -> server -> sing-box wg-wdtt-in -> BitTorrent sniffer -> egress
//
// The bridge (anonymous VK mode + auto-captcha) is brought up on the first
// connection, not at start: a bundle that merely lists this node must not keep
// dozens of TURN legs and their keepalives alive on a phone around the clock.
// It is torn down again after idle_timeout without connections (default 5m) and
// comes back on the next dial. The WireGuard config (keys/address) is fetched
// from the server via GETCONF on each bring-up.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/lazytunnel"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/awg"
	wdttclient "github.com/sagernet/sing-box/transport/wdtt"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.WDTTOutboundOptions](registry, C.TypeWDTT, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	options   option.WDTTOutboundOptions
	dnsRouter adapter.DNSRouter
	tunnel    *lazytunnel.Tunnel[*tunnelHandle]
}

// tunnelHandle is one running bridge + WireGuard device pair.
type tunnelHandle struct {
	bridge *wdttclient.ClientHandle
	device *awg.Device
}

func (h *tunnelHandle) Close() error {
	// Device first: its receive loop reads from the bridge's loopback socket.
	h.device.Close()
	h.bridge.Close()
	return nil
}

const defaultIdleTimeout = 5 * time.Minute

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WDTTOutboundOptions) (adapter.Outbound, error) {
	if options.Server == "" || options.ServerPort == 0 {
		return nil, E.New("wdtt: server and server_port are required")
	}
	if options.Password == "" {
		return nil, E.New("wdtt: password is required")
	}
	if len(options.VKHashes) == 0 {
		return nil, E.New("wdtt: at least one vk_hash is required")
	}
	idle := time.Duration(options.IdleTimeout)
	if idle == 0 {
		idle = defaultIdleTimeout
	}
	o := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeWDTT, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		options:   options,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
	}
	o.tunnel = lazytunnel.New(ctx, logger, "wdtt", idle, o.bringUp)
	return o, nil
}

func (o *Outbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage == adapter.StartStatePostStart {
		o.logger.Info("wdtt: bridge will start on the first connection (idle timeout ", o.tunnel.IdleTimeout(), ")")
	}
	return nil
}

func (o *Outbound) bringUp() (*tunnelHandle, error) {
	serverAddr := net.JoinHostPort(o.options.Server, fmt.Sprint(o.options.ServerPort))
	o.logger.Info("wdtt: starting VK-TURN bridge to ", serverAddr, " (", len(o.options.VKHashes), " hashes)")
	// On Android the bridge's bootstrap sockets (VK API/DNS/TURN) must bypass our
	// own TUN, else they loop into the not-yet-ready tunnel and time out. Source
	// the platform socket-protect control from the NetworkManager.
	var bootstrapControl control.Func
	if nm := service.FromContext[adapter.NetworkManager](o.ctx); nm != nil {
		bootstrapControl = control.Append(nm.AutoDetectInterfaceFunc(), nm.ProtectFunc())
	}
	bridge, err := wdttclient.RunClientBridge(o.ctx, wdttclient.ClientConfig{
		PeerAddr: serverAddr,
		Password: o.options.Password,
		Hashes:   o.options.VKHashes,
		DeviceID: o.options.DeviceID,
		DNS:      o.options.VKDNS,
		Obfs:     o.options.Obfs,
		Workers:  o.options.Workers,
		Control:  bootstrapControl,
	})
	if err != nil {
		return nil, E.Cause(err, "wdtt: bridge")
	}
	priv, pub, addr, err := parseWGConf(bridge.WGConfig)
	if err != nil {
		bridge.Close()
		return nil, E.Cause(err, "wdtt: parse server WireGuard config")
	}
	mtu := o.options.MTU
	if mtu == 0 {
		mtu = 1280
	}
	peerEndpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), parsePort(bridge.LocalPort))
	// WireGuard rides inside RTP inside UDP here: let the kernel fragment rather than
	// drop packets over the path MTU (same as the WireGuard endpoint)
	o.options.UDPFragmentDefault = true
	dial, err := dialer.NewWithOptions(dialer.Options{
		Context:        o.ctx,
		Options:        o.options.DialerOptions,
		DirectOutbound: true,
	})
	if err != nil {
		bridge.Close()
		return nil, err
	}
	ipc := genPlainWGIpc(priv, pub)
	dev, err := awg.NewDevice(o.ctx, o.logger, dial, ipc, awg.DeviceOpts{
		PeerEndpoint: peerEndpoint,
		Address:      []netip.Prefix{addr},
		AllowedIps:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		MTU:          mtu,
	})
	if err != nil {
		bridge.Close()
		return nil, E.Cause(err, "wdtt: create wireguard device")
	}
	if err := dev.Start(adapter.StartStateStart); err != nil {
		dev.Close()
		bridge.Close()
		return nil, E.Cause(err, "wdtt: start wireguard device")
	}
	o.logger.Info("wdtt: tunnel up (WireGuard over VK-TURN, egress via server ", serverAddr, ")")
	return &tunnelHandle{bridge: bridge, device: dev}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := o.tunnel.EnsureStarted(ctx); err != nil {
		return nil, E.Cause(err, "wdtt: start")
	}
	h, ok := o.tunnel.Handle()
	if !ok {
		return nil, E.New("wdtt: not started")
	}
	dev := h.device
	o.logger.InfoContext(ctx, "outbound connection to ", destination)
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("wdtt: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return o.tunnel.Track(N.DialSerial(ctx, dev, network, destination, addrs))
	}
	return o.tunnel.Track(dev.DialContext(ctx, network, destination))
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := o.tunnel.EnsureStarted(ctx); err != nil {
		return nil, E.Cause(err, "wdtt: start")
	}
	h, ok := o.tunnel.Handle()
	if !ok {
		return nil, E.New("wdtt: not started")
	}
	dev := h.device
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("wdtt: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		conn, _, err := N.ListenSerial(ctx, dev, destination, addrs)
		return o.tunnel.TrackPacket(conn, err)
	}
	return o.tunnel.TrackPacket(dev.ListenPacket(ctx, destination))
}

func (o *Outbound) Close() error {
	return o.tunnel.Close()
}

// parseWGConf extracts PrivateKey, peer PublicKey and the client Address from a
// WireGuard .conf ([Interface]/[Peer]) as returned by the wdtt server GETCONF.
func parseWGConf(conf string) (priv, pub string, addr netip.Prefix, err error) {
	sc := bufio.NewScanner(strings.NewReader(conf))
	var addrStr string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.ToLower(k))
		v = strings.TrimSpace(v)
		switch k {
		case "privatekey":
			priv = v
		case "publickey":
			pub = v
		case "address":
			addrStr = v
		}
	}
	if priv == "" || pub == "" || addrStr == "" {
		return "", "", netip.Prefix{}, fmt.Errorf("missing PrivateKey/PublicKey/Address")
	}
	if a, perr := netip.ParsePrefix(addrStr); perr == nil {
		addr = a
	} else if ip, ierr := netip.ParseAddr(addrStr); ierr == nil {
		addr = netip.PrefixFrom(ip, ip.BitLen())
	} else {
		return "", "", netip.Prefix{}, fmt.Errorf("bad Address %q", addrStr)
	}
	return priv, pub, addr, nil
}

func genPlainWGIpc(privB64, pubB64 string) string {
	priv, _ := base64.StdEncoding.DecodeString(privB64)
	pub, _ := base64.StdEncoding.DecodeString(pubB64)
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s", hex.EncodeToString(priv))
	fmt.Fprintf(&b, "\npublic_key=%s", hex.EncodeToString(pub))
	b.WriteString("\nendpoint=127.0.0.1:1") // placeholder; PeerEndpoint bind supplies the real one
	// No WireGuard keepalive: the bridge keeps its TURN/DTLS legs alive itself and
	// the peer is loopback, so there is no NAT mapping to refresh.
	b.WriteString("\nallowed_ip=0.0.0.0/0")
	b.WriteString("\nallowed_ip=::/0")
	return b.String()
}

func parsePort(s string) uint16 {
	var p int
	fmt.Sscanf(s, "%d", &p)
	return uint16(p)
}
