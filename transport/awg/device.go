package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type DeviceOpts struct {
	UseIntegratedTun    bool
	PeerEndpoint        netip.AddrPort
	Reserved            [3]uint8
	ReservedForEndpoint map[netip.AddrPort][3]uint8
	Address             []netip.Prefix
	AllowedIps          []netip.Prefix
	ExcludedIps         []netip.Prefix
	MTU                 uint32
	// Bind, if non-nil, overrides the default dial/peerEndpoint bind — used by
	// masque-wg to run WireGuard over a single MASQUE CONNECT-UDP flow.
	Bind conn.Bind
}

type Device struct {
	awgDevice *device.Device
	tun       tunAdapter
	bind      conn.Bind
	logger    *device.Logger
	ipcConfig string
}

func NewDevice(ctx context.Context, logger logger.ContextLogger, dial network.Dialer, ipcConfig string, opts DeviceOpts) (*Device, error) {
	var (
		tun tunAdapter
		err error
	)

	if opts.UseIntegratedTun {
		tun, err = newSystemTun(ctx, opts.Address, opts.AllowedIps, opts.ExcludedIps, opts.MTU, logger)
		if err != nil {
			return nil, E.Cause(err, "create tunnel")
		}
	} else {
		tun, err = newNetworkTun(opts.Address, opts.MTU)
		if err != nil {
			return nil, err
		}
	}

	awgLogger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}

	devBind := opts.Bind
	if devBind == nil {
		devBind = newBind(ctx, dial, opts.PeerEndpoint, opts.Reserved, opts.ReservedForEndpoint)
	}
	return &Device{
		tun:       tun,
		bind:      devBind,
		logger:    awgLogger,
		ipcConfig: ipcConfig,
	}, nil
}

func (d *Device) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	d.awgDevice = device.NewDevice(d.tun, d.bind, d.logger)
	if err := d.awgDevice.IpcSet(d.ipcConfig); err != nil {
		return E.Cause(err, "set ipc config")
	}

	if err := d.tun.Start(); err != nil {
		return E.Cause(err, "tun start")
	}

	return d.awgDevice.Up()
}

// IpcUpdate applies an incremental WireGuard IPC update to the running device.
// Used to set a peer's endpoint AFTER the device has started, once the peer FQDN
// can be resolved (i.e. after the Android VpnService/socket-protect is up) — the
// awg endpoint defers peer-endpoint resolution out of NewEndpoint to avoid the
// "no VpnService for socket protect" crash during config creation.
func (d *Device) IpcUpdate(s string) error {
	if d.awgDevice == nil {
		return E.New("awg: device not started")
	}
	return d.awgDevice.IpcSet(s)
}

func (d *Device) Close() error {
	if d.awgDevice != nil {
		d.awgDevice.Close()
	}
	return nil
}

func (d *Device) InterfaceUpdated() {
	if d.awgDevice == nil {
		return
	}
	if err := d.awgDevice.BindUpdate(); err != nil {
		d.logger.Errorf("UDP bind update failed: %v", err)
		return
	}
	d.awgDevice.SendKeepalivesToPeersWithCurrentKeypair()
}

func (d *Device) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	return d.tun.DialContext(ctx, network, destination)
}

func (d *Device) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return d.tun.ListenPacket(ctx, destination)
}
