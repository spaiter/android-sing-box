package awg

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestValidateObfuscationOptionsAcceptsRecommendedValues(t *testing.T) {
	err := validateObfuscationOptions(option.AwgEndpointOptions{
		Jc:   12,
		Jmin: 50,
		Jmax: 1000,
		S1:   64,
		S2:   64,
		S3:   64,
		S4:   64,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateObfuscationOptionsRejectsUnsafeValues(t *testing.T) {
	tests := map[string]option.AwgEndpointOptions{
		"negative jc":     {Jc: -1},
		"excessive jc":    {Jc: awgMaxJunkPacketCount + 1, Jmin: 50, Jmax: 1000},
		"missing jmin":    {Jc: 1, Jmax: 1000},
		"missing jmax":    {Jc: 1, Jmin: 50},
		"inverted range":  {Jc: 1, Jmin: 1000, Jmax: 50},
		"excessive jmax":  {Jc: 1, Jmin: 50, Jmax: awgMaxJunkPacketSize + 1},
		"negative s1":     {S1: -1},
		"excessive s1":    {S1: awgMaxHandshakePad + 1},
		"excessive s4":    {S4: awgMaxTransportPad + 1},
		"standalone jmin": {Jmin: 50},
	}
	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateObfuscationOptions(options); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestResolveClientBindSinglePeerEndpoint(t *testing.T) {
	ipv6Endpoint := netip.MustParseAddrPort("[2606:4700:110:8dd6:7d68:3501:b0b8:d216]:2408")
	tests := map[string]struct {
		options option.AwgEndpointOptions
		want    netip.AddrPort
	}{
		"direct single peer": {
			options: option.AwgEndpointOptions{
				Peers: []option.AwgPeerOptions{{
					Address: ipv6Endpoint.Addr().String(),
					Port:    ipv6Endpoint.Port(),
				}},
			},
		},
		"detoured single peer": {
			options: option.AwgEndpointOptions{
				DialerOptions: option.DialerOptions{Detour: "proxy"},
				Peers: []option.AwgPeerOptions{{
					Address: ipv6Endpoint.Addr().String(),
					Port:    ipv6Endpoint.Port(),
				}},
			},
			want: ipv6Endpoint,
		},
		"detoured multi peer": {
			options: option.AwgEndpointOptions{
				DialerOptions: option.DialerOptions{Detour: "proxy"},
				Peers: []option.AwgPeerOptions{
					{
						Address: ipv6Endpoint.Addr().String(),
						Port:    ipv6Endpoint.Port(),
					},
					{
						Address: "192.0.2.1",
						Port:    2408,
					},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			endpoint, err := resolveClientBindSinglePeerEndpoint(test.options, nil)
			if err != nil {
				t.Fatal(err)
			}
			if endpoint != test.want {
				t.Fatalf("endpoint mismatch: got %v, want %v", endpoint, test.want)
			}
		})
	}
}

func TestResolveClientBindSinglePeerEndpointResolvesDetouredDomain(t *testing.T) {
	options := option.AwgEndpointOptions{
		DialerOptions: option.DialerOptions{Detour: "proxy"},
		Peers: []option.AwgPeerOptions{{
			Address: "example.com",
			Port:    2408,
		}},
	}
	resolvedAddr := netip.MustParseAddr("2001:db8::1")

	endpoint, err := resolveClientBindSinglePeerEndpoint(options, func(domain string) (netip.Addr, error) {
		if domain != "example.com" {
			t.Fatalf("domain mismatch: got %q", domain)
		}
		return resolvedAddr, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := netip.AddrPortFrom(resolvedAddr, 2408)
	if endpoint != want {
		t.Fatalf("endpoint mismatch: got %v, want %v", endpoint, want)
	}
}
