package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ conn.Bind = (*bind_adapter)(nil)

type bind_adapter struct {
	conn4           net.PacketConn
	conn6           net.PacketConn
	dialer          N.Dialer
	ctx             context.Context
	mutex           sync.Mutex
	peerEndpoint    netip.AddrPort
	reserved        [3]uint8
	reservedForPeer map[netip.AddrPort][3]uint8
	hasReserved     bool
}

func newBind(ctx context.Context, dial N.Dialer, peerEndpoint netip.AddrPort, reserved [3]uint8, reservedForEndpoint map[netip.AddrPort][3]uint8) conn.Bind {
	hasReserved := reserved != [3]uint8{}
	if !hasReserved {
		for _, peerReserved := range reservedForEndpoint {
			if peerReserved != [3]uint8{} {
				hasReserved = true
				break
			}
		}
	}
	return &bind_adapter{
		ctx:             ctx,
		dialer:          dial,
		peerEndpoint:    peerEndpoint,
		reserved:        reserved,
		reservedForPeer: reservedForEndpoint,
		hasReserved:     hasReserved,
	}
}

func (b *bind_adapter) connect(addr netip.Addr, port uint16) (net.PacketConn, error) {
	if b.peerEndpoint.IsValid() && b.peerEndpoint.Addr() == addr {
		udpConn, err := b.dialer.DialContext(b.ctx, N.NetworkUDP, M.SocksaddrFromNetIP(b.peerEndpoint))
		if err != nil {
			return nil, err
		}
		return bufio.NewUnbindPacketConn(udpConn), nil
	}
	return b.dialer.ListenPacket(b.ctx, M.Socksaddr{Addr: addr, Port: port})
}

func (b *bind_adapter) receive(c net.PacketConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		n, addr, err := c.ReadFrom(packets[0])
		if err != nil {
			return 0, E.Cause(err, "read data")
		}

		bindEp, err := b.ParseEndpoint(addr.String())
		if err != nil {
			return 0, E.Cause(err, "parse endpoint")
		}
		if b.hasReserved && n > 3 {
			buf := packets[0]
			buf[1], buf[2], buf[3] = 0, 0, 0
		}

		sizes[0] = n
		eps[0] = bindEp
		return 1, nil
	}
}

func (b *bind_adapter) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.conn4 != nil || b.conn6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	if b.peerEndpoint.IsValid() {
		conn, err := b.connect(b.peerEndpoint.Addr(), port)
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return nil, 0, E.Cause(err, "create single peer connection")
		}
		if conn != nil {
			if b.peerEndpoint.Addr().Is6() {
				b.conn6 = conn
			} else {
				b.conn4 = conn
			}
			fns = append(fns, b.receive(conn))
		}
		return fns, port, nil
	}

	conn4, err := b.connect(netip.IPv4Unspecified(), port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, E.Cause(err, "create ipv4 connection")
	}
	if conn4 != nil {
		fns = append(fns, b.receive(conn4))
	}

	conn6, err := b.connect(netip.IPv6Unspecified(), port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, E.Cause(err, "create ipv6 connection")
	}
	if conn6 != nil {
		fns = append(fns, b.receive(conn6))
	}

	b.conn4 = conn4
	b.conn6 = conn6

	return fns, port, nil
}

func (b *bind_adapter) Close() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var err4, err6 error

	if b.conn4 != nil {
		err4 = ignoreClosedConnError(b.conn4.Close())
		b.conn4 = nil
	}

	if b.conn6 != nil {
		err6 = ignoreClosedConnError(b.conn6.Close())
		b.conn6 = nil
	}

	return errors.Join(err4, err6)
}

func ignoreClosedConnError(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func (b *bind_adapter) SetMark(mark uint32) error {
	return nil
}

func (b *bind_adapter) Send(bufs [][]byte, ep conn.Endpoint) error {
	var conn net.PacketConn
	if ep.DstIP().Is6() {
		conn = b.conn6
	} else {
		conn = b.conn4
	}

	if conn == nil {
		return errors.ErrUnsupported
	}

	bindEp, ok := ep.(*bind_endpoint)
	if !ok {
		return errors.ErrUnsupported
	}

	udpAddr := &net.UDPAddr{
		IP:   bindEp.AddrPort.Addr().AsSlice(),
		Port: int(bindEp.AddrPort.Port()),
	}

	for _, buf := range bufs {
		if b.hasReserved && len(buf) > 3 {
			reserved, loaded := b.reservedForPeer[bindEp.AddrPort]
			if !loaded {
				reserved = b.reserved
			}
			copy(buf[1:4], reserved[:])
		}
		if _, err := conn.WriteTo(buf, udpAddr); err != nil {
			return err
		}
	}

	return nil
}

func (b *bind_adapter) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, E.Cause(err, "parse addrport")
	}

	return &bind_endpoint{AddrPort: ap}, nil
}

func (b *bind_adapter) BatchSize() int {
	return 1
}

var _ conn.Endpoint = (*bind_endpoint)(nil)

type bind_endpoint struct {
	AddrPort netip.AddrPort
}

func (e bind_endpoint) ClearSrc() {
}

func (e bind_endpoint) SrcToString() string {
	return ""
}

func (e bind_endpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e bind_endpoint) DstToBytes() []byte {
	b, err := e.AddrPort.MarshalBinary()
	if err != nil {
		return nil
	}
	return b
}

func (e bind_endpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

func (e bind_endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
