package wdtt

// fulltest.go — server-side reproduction of the phone's exact WDTT data path:
// RunClientBridge (VK-TURN/obfs/DTLS) + embedded awg WireGuard device + an HTTPS
// GET through it. Lets us debug "tunnel up but no traffic" without a phone.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/awg"
	wdttclient "github.com/sagernet/sing-box/transport/wdtt"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// plainDialer is a minimal N.Dialer for the WG device's socket to the local
// bridge port (no TUN on the server, so no protection needed).
type plainDialer struct{}

func (plainDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, dest.String())
}

func (plainDialer) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, "udp", ":0")
}

// RunFullPathTest brings up the full WDTT outbound (bridge + WG device) and does
// an HTTPS GET to https://<ipHost>/cdn-cgi/trace through it (ipHost must be a
// literal IP, e.g. 1.1.1.1, so no DNS is needed). Returns the trace body.
func RunFullPathTest(ctx context.Context, cfg wdttclient.ClientConfig, mtu uint32, ipHost string) (string, error) {
	bridge, err := wdttclient.RunClientBridge(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("bridge: %w", err)
	}
	defer bridge.Close()
	priv, pub, addr, err := parseWGConf(bridge.WGConfig)
	if err != nil {
		return "", fmt.Errorf("parse wgconf: %w", err)
	}
	if mtu == 0 {
		mtu = 1000
	}
	peerEndpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), parsePort(bridge.LocalPort))
	ipc := genPlainWGIpc(priv, pub)
	dev, err := awg.NewDevice(ctx, logger.NOP(), plainDialer{}, ipc, awg.DeviceOpts{
		PeerEndpoint: peerEndpoint,
		Address:      []netip.Prefix{addr},
		AllowedIps:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		MTU:          mtu,
	})
	if err != nil {
		return "", fmt.Errorf("wg device: %w", err)
	}
	if err := dev.Start(adapter.StartStateStart); err != nil {
		return "", fmt.Errorf("wg start: %w", err)
	}
	defer dev.Close()

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dev.DialContext(ctx, network, M.ParseSocksaddr(address))
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + ipHost + "/cdn-cgi/trace")
	if err != nil {
		return "", fmt.Errorf("GET via tunnel: %w", err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	var out string
	for i := 0; i < 6; i++ {
		line, e := br.ReadString('\n')
		out += line
		if e != nil {
			break
		}
	}
	return fmt.Sprintf("HTTP %s\n%s", resp.Status, out), nil
}
