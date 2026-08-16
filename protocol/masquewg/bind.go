package masquewg

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	E "github.com/sagernet/sing/common/exceptions"
)

// masqueBind implements amneziawg-go's conn.Bind over a single MASQUE CONNECT-UDP
// flow (a net.PacketConn). Unlike a real UDP socket there is exactly one peer —
// the server's WireGuard listener behind the proxy — so Send ignores the endpoint
// and always writes to the flow, and receive reads from it. //H
type masqueBind struct {
	mu     sync.Mutex
	pc     net.PacketConn // the masque.Conn, set via SetConn
	closed bool
	ready  chan struct{} // closed once pc is installed
	once   sync.Once
}

var _ conn.Bind = (*masqueBind)(nil)

func newMasqueBind() *masqueBind { return &masqueBind{ready: make(chan struct{})} }

// SetConn installs the established MASQUE flow and unblocks Open.
func (b *masqueBind) SetConn(pc net.PacketConn) {
	b.mu.Lock()
	b.pc = pc
	b.closed = false
	b.mu.Unlock()
	b.once.Do(func() { close(b.ready) })
}

func (b *masqueBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// device.Up() may call Open before/after the MASQUE flow is dialed; wait for it.
	select {
	case <-b.ready:
	case <-time.After(30 * time.Second):
		return nil, 0, E.New("masque-wg: timed out waiting for MASQUE flow")
	}
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return nil, 0, E.New("masque-wg: bind opened before MASQUE flow established")
	}
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, _, err := pc.ReadFrom(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = masqueEndpoint{}
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *masqueBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	pc := b.pc
	closed := b.closed
	b.mu.Unlock()
	if closed || pc == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, masqueUDPAddr); err != nil {
			return err
		}
	}
	return nil
}

// Close is a no-op for the flow. WireGuard's BindUpdate closes and reopens the
// bind on IpcSet/Up; the MASQUE flow is persistent and owned by the Outbound, so
// closing/niling it here would break the rebind (Open would then see no flow).
// Outbound.Close() closes the actual MASQUE conn. //H
func (b *masqueBind) Close() error { return nil }

func (b *masqueBind) SetMark(uint32) error { return nil }
func (b *masqueBind) BatchSize() int       { return 1 }

func (b *masqueBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return masqueEndpoint{}, nil
}

// masqueUDPAddr is a throwaway address; masque.Conn is a connected CONNECT-UDP
// flow and ignores the WriteTo address.
var masqueUDPAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

var _ conn.Endpoint = masqueEndpoint{}

// masqueEndpoint is the single constant peer endpoint (the server WG behind the
// proxy). WireGuard only needs it to be stable and comparable.
type masqueEndpoint struct{}

func (masqueEndpoint) ClearSrc()           {}
func (masqueEndpoint) SrcToString() string { return "" }
func (masqueEndpoint) DstToString() string { return "masque:0" }
func (masqueEndpoint) DstToBytes() []byte  { return []byte{0} }
func (masqueEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (masqueEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

var _ = errors.Is
