// Package lazytunnel brings an expensive tunnel (an embedded WireGuard device
// over some transport) up on the first connection and tears it down again once
// nothing has used it for a while.
//
// A subscription bundle lists every method the user may pick; without this, each
// tunnel outbound would hold its transport, keepalives and goroutines alive on
// the phone around the clock even while another node is selected.
package lazytunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// Tunnel manages the lifecycle of one handle of type H.
type Tunnel[H io.Closer] struct {
	ctx         context.Context
	logger      logger.Logger
	name        string
	idleTimeout time.Duration
	bringUp     func() (H, error)

	startMu sync.Mutex // serialises bring-up and teardown
	mu      sync.Mutex // guards the fields below
	started bool
	handle  H
	reaper  context.CancelFunc

	active  atomic.Int32 // connections handed out and not yet closed
	lastUse atomic.Int64 // unix nanos of the last dial or close
}

// New creates a Tunnel. name prefixes log lines; bringUp is called under the
// start lock whenever the tunnel has to come up; the handle it returns is closed
// on teardown. idleTimeout <= 0 disables idle teardown.
func New[H io.Closer](ctx context.Context, logger logger.Logger, name string, idleTimeout time.Duration, bringUp func() (H, error)) *Tunnel[H] {
	return &Tunnel[H]{ctx: ctx, logger: logger, name: name, idleTimeout: idleTimeout, bringUp: bringUp}
}

// IdleTimeout returns the configured idle timeout.
func (t *Tunnel[H]) IdleTimeout() time.Duration { return t.idleTimeout }

// Ready reports whether the tunnel is currently up.
func (t *Tunnel[H]) Ready() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.started
}

// Handle returns the current handle and whether the tunnel is up.
func (t *Tunnel[H]) Handle() (H, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.handle, t.started
}

// EnsureStarted brings the tunnel up if it is not running. Concurrent callers
// wait for the same bring-up. It also counts as a use.
func (t *Tunnel[H]) EnsureStarted(ctx context.Context) error {
	t.Touch()
	if t.Ready() {
		return nil
	}
	t.startMu.Lock()
	defer t.startMu.Unlock()
	if t.Ready() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	handle, err := t.bringUp()
	if err != nil {
		return err
	}
	var reaperCtx context.Context
	var cancel context.CancelFunc
	if t.idleTimeout > 0 {
		reaperCtx, cancel = context.WithCancel(t.ctx)
	}
	t.mu.Lock()
	t.handle = handle
	t.reaper = cancel
	t.started = true
	t.mu.Unlock()
	t.Touch()
	if reaperCtx != nil {
		go t.reapWhenIdle(reaperCtx)
	}
	return nil
}

// Touch records that the tunnel was just used.
func (t *Tunnel[H]) Touch() { t.lastUse.Store(time.Now().UnixNano()) }

// Close tears the tunnel down; EnsureStarted may bring it back later.
func (t *Tunnel[H]) Close() error {
	t.startMu.Lock()
	defer t.startMu.Unlock()
	return t.tearDown()
}

func (t *Tunnel[H]) tearDown() error {
	t.mu.Lock()
	handle, started := t.handle, t.started
	reaper := t.reaper
	var zero H
	t.handle = zero
	t.reaper = nil
	t.started = false
	t.mu.Unlock()
	if reaper != nil {
		reaper()
	}
	if started {
		return handle.Close()
	}
	return nil
}

func (t *Tunnel[H]) reapWhenIdle(ctx context.Context) {
	tick := t.idleTimeout / 4
	if tick < 15*time.Second {
		tick = 15 * time.Second
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if t.ReapOnce() {
			return
		}
	}
}

// ReapOnce performs one idle check and reports whether it tore the tunnel down.
func (t *Tunnel[H]) ReapOnce() bool {
	if t.idleTimeout <= 0 || t.active.Load() > 0 {
		return false
	}
	idle := time.Since(time.Unix(0, t.lastUse.Load()))
	if idle < t.idleTimeout {
		return false
	}
	t.startMu.Lock()
	defer t.startMu.Unlock()
	if t.active.Load() != 0 || time.Since(time.Unix(0, t.lastUse.Load())) < t.idleTimeout || !t.Ready() {
		return false
	}
	t.logger.Info(t.name, ": idle for ", idle.Truncate(time.Second), ", tearing the tunnel down")
	t.tearDown()
	return true
}

// Track wraps a connection so the reaper knows while it is open.
func (t *Tunnel[H]) Track(conn net.Conn, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	t.active.Add(1)
	return &trackedConn{Conn: conn, release: t.released}, nil
}

// TrackPacket is Track for packet connections.
func (t *Tunnel[H]) TrackPacket(conn net.PacketConn, err error) (net.PacketConn, error) {
	if err != nil {
		return nil, err
	}
	t.active.Add(1)
	return &trackedPacketConn{PacketConn: conn, release: t.released}, nil
}

// Active returns the number of tracked connections still open.
func (t *Tunnel[H]) Active() int32 { return t.active.Load() }

func (t *Tunnel[H]) released() {
	t.Touch()
	t.active.Add(-1)
}

type trackedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func (c *trackedConn) Upstream() any { return c.Conn }

type trackedPacketConn struct {
	net.PacketConn
	release func()
	once    sync.Once
}

func (c *trackedPacketConn) Close() error {
	c.once.Do(c.release)
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) Upstream() any { return c.PacketConn }
