package wdtt

// Native WG-over-VK (WDTT) client outbound. Mirrors the awg outbound but the
// WireGuard peer endpoint is the in-process VK-TURN bridge (127.0.0.1:<port>):
//
//	sing-box WG (netstack) -> 127.0.0.1:localPort -> [wdtt bridge: VK-TURN/WRAP/RTP/DTLS]
//	  -> server -> sing-box wg-wdtt-in -> BitTorrent sniffer -> egress
//
// The bridge (anonymous VK mode + auto-captcha) is started lazily at PostStart;
// the WireGuard config (keys/address) is fetched from the server via GETCONF.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
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

	mu      sync.Mutex
	started bool
	bridge  *wdttclient.ClientHandle
	device  *awg.Device
}

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
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeWDTT, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		options:   options,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
	}, nil
}

func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
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
		return E.Cause(err, "wdtt: bridge")
	}
	priv, pub, addr, err := parseWGConf(bridge.WGConfig)
	if err != nil {
		bridge.Close()
		return E.Cause(err, "wdtt: parse server WireGuard config")
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
		return err
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
		return E.Cause(err, "wdtt: create wireguard device")
	}
	if err := dev.Start(adapter.StartStateStart); err != nil {
		dev.Close()
		bridge.Close()
		return E.Cause(err, "wdtt: start wireguard device")
	}
	o.mu.Lock()
	o.bridge = bridge
	o.device = dev
	o.started = true
	o.mu.Unlock()
	o.logger.Info("wdtt: tunnel up (WireGuard over VK-TURN, egress via server ", serverAddr, ")")
	return nil
}

func (o *Outbound) ready() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.started
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !o.ready() {
		return nil, E.New("wdtt: not started")
	}
	o.logger.InfoContext(ctx, "outbound connection to ", destination)
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("wdtt: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, o.device, network, destination, addrs)
	}
	return o.device.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !o.ready() {
		return nil, E.New("wdtt: not started")
	}
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("wdtt: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		conn, _, err := N.ListenSerial(ctx, o.device, destination, addrs)
		return conn, err
	}
	return o.device.ListenPacket(ctx, destination)
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	dev := o.device
	bridge := o.bridge
	o.started = false
	o.device = nil
	o.bridge = nil
	o.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	if bridge != nil {
		bridge.Close()
	}
	return nil
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
	b.WriteString("\npersistent_keepalive_interval=25")
	b.WriteString("\nallowed_ip=0.0.0.0/0")
	b.WriteString("\nallowed_ip=::/0")
	return b.String()
}

func parsePort(s string) uint16 {
	var p int
	fmt.Sscanf(s, "%d", &p)
	return uint16(p)
}
