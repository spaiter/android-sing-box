// obfs_rtp.go — thin client-side adapters over the vendored rtpopus2/rtpopus3
// codecs, selected via ObfsMode. Both mask each TURN payload as a modern-WebRTC
// RTP/opus packet (RFC 8285 extensions), which evades VK's media-vs-nonmedia
// traffic shaping far better than the legacy v1 masking in obfs.go. rtpopus3
// adds abs-send-time, variable timestamp step, and VAD/loss mimicry on top of
// rtpopus2. The wdtt-relay server auto-detects the profile per packet, so v1,
// rtpopus2 and rtpopus3 clients coexist during rollout.

package wdtt

import (
	"github.com/sagernet/sing-box/transport/wdtt/rtpopus2"
	"github.com/sagernet/sing-box/transport/wdtt/rtpopus3"
)

const (
	obfsModeRTPOpus2 = "rtpopus2"
	obfsModeRTPOpus3 = "rtpopus3"
)

// rtpCodec is a per-session client obfuscation codec. wrap allocates a fresh
// wire packet (mirrors obfsWrapPacket); unwrap writes plaintext into dst without
// mutating wire (mirrors obfsUnwrapPacket). One codec serves both pumps of a
// session — the send state is internally synchronised and unwrap only reads the
// shared AEAD.
type rtpCodec interface {
	wrap(payload []byte) ([]byte, error)
	unwrap(wire, dst []byte) (int, error)
}

type r2codec struct{ c *rtpopus2.Conn }

func (a r2codec) wrap(p []byte) ([]byte, error) {
	dst := make([]byte, a.c.MaxWire(len(p)))
	n, err := a.c.WrapInto(dst, p)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
func (a r2codec) unwrap(wire, dst []byte) (int, error) { return a.c.UnwrapTo(wire, dst) }

type r3codec struct{ c *rtpopus3.Conn }

func (a r3codec) wrap(p []byte) ([]byte, error) {
	dst := make([]byte, a.c.MaxWire(len(p)))
	n, err := a.c.WrapInto(dst, p)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
func (a r3codec) unwrap(wire, dst []byte) (int, error) { return a.c.UnwrapTo(wire, dst) }

// newRTPCodec builds the client codec (direction bit clear) for the profile.
// Returns (nil, nil) for any non-rtpopus profile so the caller falls back to the
// legacy v1 masking.
func newRTPCodec(profile string, key []byte) (rtpCodec, error) {
	switch profile {
	case obfsModeRTPOpus2:
		c, err := rtpopus2.NewConn(key, false)
		if err != nil {
			return nil, err
		}
		return r2codec{c}, nil
	case obfsModeRTPOpus3:
		c, err := rtpopus3.NewConn(key, false)
		if err != nil {
			return nil, err
		}
		return r3codec{c}, nil
	default:
		return nil, nil
	}
}
