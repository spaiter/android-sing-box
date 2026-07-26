package awg

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.Dialer = (*fakeDialer)(nil)

type fakeDialer struct {
	dialCount   int
	listenCount int
	dialDest    M.Socksaddr
	listenDests []M.Socksaddr
	remoteAddr  net.Addr
}

func (d *fakeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dialCount++
	d.dialDest = destination
	return &fakeConn{
		localAddr:  &net.UDPAddr{IP: net.IPv6zero, Port: 12345},
		remoteAddr: d.remoteAddr,
	}, nil
}

func (d *fakeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.listenCount++
	d.listenDests = append(d.listenDests, destination)
	return &fakePacketConn{
		localAddr: &net.UDPAddr{
			IP:   destination.Addr.AsSlice(),
			Port: int(destination.Port),
		},
	}, nil
}

type fakeConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *fakeConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

func (c *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *fakeConn) Close() error {
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *fakeConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type fakePacketConn struct {
	localAddr net.Addr
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return len(b), nil
}

func (c *fakePacketConn) Close() error {
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *fakePacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *fakePacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *fakePacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestBindOpenWithoutPeerEndpointUsesPacketListeners(t *testing.T) {
	dialer := &fakeDialer{}
	bind := newBind(context.Background(), dialer, netip.AddrPort{}, [3]uint8{}, nil)

	receiveFuncs, actualPort, err := bind.Open(1234)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bind.Close(); err != nil {
			t.Fatal(err)
		}
	})

	if actualPort != 1234 {
		t.Fatalf("actual port mismatch: got %d, want 1234", actualPort)
	}
	if len(receiveFuncs) != 2 {
		t.Fatalf("receive func count mismatch: got %d, want 2", len(receiveFuncs))
	}
	if dialer.dialCount != 0 {
		t.Fatalf("dial count mismatch: got %d, want 0", dialer.dialCount)
	}
	if dialer.listenCount != 2 {
		t.Fatalf("listen count mismatch: got %d, want 2", dialer.listenCount)
	}
}

func TestBindOpenWithPeerEndpointUsesConnectedDial(t *testing.T) {
	peerEndpoint := netip.MustParseAddrPort("[2001:db8::1]:2408")
	dialer := &fakeDialer{
		remoteAddr: &net.UDPAddr{
			IP:   peerEndpoint.Addr().AsSlice(),
			Port: int(peerEndpoint.Port()),
		},
	}
	bind := newBind(context.Background(), dialer, peerEndpoint, [3]uint8{}, nil)

	receiveFuncs, actualPort, err := bind.Open(1234)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bind.Close(); err != nil {
			t.Fatal(err)
		}
	})

	if actualPort != 1234 {
		t.Fatalf("actual port mismatch: got %d, want 1234", actualPort)
	}
	if len(receiveFuncs) != 1 {
		t.Fatalf("receive func count mismatch: got %d, want 1", len(receiveFuncs))
	}
	if dialer.dialCount != 1 {
		t.Fatalf("dial count mismatch: got %d, want 1", dialer.dialCount)
	}
	if dialer.listenCount != 0 {
		t.Fatalf("listen count mismatch: got %d, want 0", dialer.listenCount)
	}
	if dialer.dialDest.AddrPort() != peerEndpoint {
		t.Fatalf("dial destination mismatch: got %v, want %v", dialer.dialDest, peerEndpoint)
	}
}
