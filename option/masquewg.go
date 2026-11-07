package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

// AwgOptions holds AmneziaWG obfuscation parameters shared by the embedded
// WireGuard device of a masque-wg outbound. They must match the server's awg
// endpoint so the handshake is accepted through the tunnel.
type AwgOptions struct {
	Jc   int    `json:"jc,omitempty"`
	Jmin int    `json:"jmin,omitempty"`
	Jmax int    `json:"jmax,omitempty"`
	S1   int    `json:"s1,omitempty"`
	S2   int    `json:"s2,omitempty"`
	S3   int    `json:"s3,omitempty"`
	S4   int    `json:"s4,omitempty"`
	H1   string `json:"h1,omitempty"`
	H2   string `json:"h2,omitempty"`
	H3   string `json:"h3,omitempty"`
	H4   string `json:"h4,omitempty"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
}

// MASQUEWGOutboundOptions configures the client side of the self-hosted
// MASQUE(CONNECT-UDP)+WireGuard pair: it dials the masque-wg server over HTTP/3,
// opens a CONNECT-UDP association, and runs an embedded WireGuard/AmneziaWG
// device whose UDP socket rides that association. Exposes a normal proxy outbound.
type MASQUEWGOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Path string `json:"path,omitempty"` // must match server, default "/m"
	// Embedded WireGuard/AmneziaWG parameters.
	PrivateKey                  string                           `json:"private_key"`
	PeerPublicKey               string                           `json:"peer_public_key"`
	PreSharedKey                string                           `json:"pre_shared_key,omitempty"`
	LocalAddress                badoption.Listable[netip.Prefix] `json:"local_address"` // client tunnel IPs, e.g. ["10.10.0.5/32"]
	MTU                         uint32                           `json:"mtu,omitempty"` // default 1280 (room under MASQUE/QUIC)
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
	// IdleTimeout: tear the MASQUE flow + WG device down after this long without
	// connections; they come back on the next dial. Default 2m.
	IdleTimeout badoption.Duration `json:"idle_timeout,omitempty"`
	Awg         AwgOptions         `json:"awg,omitempty"`
}
