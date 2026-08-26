package option

import "github.com/sagernet/sing/common/json/badoption"

// WDTTOutboundOptions configures a native WG-over-VK (WDTT) client outbound.
// The outbound runs the VK-TURN/WRAP/RTP/DTLS bridge internally (anonymous VK
// mode, auto-captcha), fetches its WireGuard config from the server via GETCONF,
// and runs an embedded WireGuard device over the bridge. Requires our fork core.
type WDTTOutboundOptions struct {
	DialerOptions
	ServerOptions                              // wdtt DTLS server (host + port)
	Password      string                       `json:"password"`
	VKHashes      badoption.Listable[string]   `json:"vk_hashes"`
	DeviceID      string                       `json:"device_id,omitempty"`
	VKDNS         string                       `json:"vk_dns,omitempty"`  // yandex (default)/cloudflare/google
	Obfs          string                       `json:"obfs,omitempty"`    // audio (default)/video/rtpopus2/rtpopus3
	Workers       int                          `json:"workers,omitempty"` // TURN workers (default 24)
	MTU           uint32                       `json:"mtu,omitempty"`
}
