package lazytunnel

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type handle struct{ closed *atomic.Int32 }

func (h handle) Close() error { h.closed.Add(1); return nil }

func newTestTunnel(idle time.Duration) (*Tunnel[handle], *atomic.Int32, *atomic.Int32) {
	var ups, closes atomic.Int32
	t := New(context.Background(), logger.NOP(), "test", idle, func() (handle, error) {
		ups.Add(1)
		return handle{closed: &closes}, nil
	})
	return t, &ups, &closes
}

func TestLazyBringUpOnce(t *testing.T) {
	tun, ups, _ := newTestTunnel(time.Minute)
	if tun.Ready() {
		t.Fatal("tunnel up before first use")
	}
	for i := 0; i < 3; i++ {
		if err := tun.EnsureStarted(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if ups.Load() != 1 || !tun.Ready() {
		t.Fatalf("bringUp called %d times, ready=%v", ups.Load(), tun.Ready())
	}
}

func TestBringUpErrorIsNotSticky(t *testing.T) {
	fail := true
	tun := New(context.Background(), logger.NOP(), "test", time.Minute, func() (handle, error) {
		if fail {
			return handle{}, errors.New("boom")
		}
		return handle{closed: new(atomic.Int32)}, nil
	})
	if err := tun.EnsureStarted(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	fail = false
	if err := tun.EnsureStarted(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The reaper must tear the tunnel down once nothing used it for idleTimeout.
func TestReaperTearsDownIdleTunnel(t *testing.T) {
	tun, _, closes := newTestTunnel(60 * time.Millisecond)
	if err := tun.EnsureStarted(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tun.ReapOnce() {
		t.Fatal("fresh tunnel reaped")
	}
	tun.lastUse.Store(time.Now().Add(-time.Second).UnixNano())
	if !tun.ReapOnce() || tun.Ready() || closes.Load() != 1 {
		t.Fatalf("idle tunnel not torn down (ready=%v closes=%d)", tun.Ready(), closes.Load())
	}
	// and it comes back on the next use
	if err := tun.EnsureStarted(context.Background()); err != nil || !tun.Ready() {
		t.Fatal("tunnel did not come back")
	}
}

// A connection that is still open keeps the tunnel, no matter how old lastUse is.
func TestReaperKeepsTunnelWithActiveConnection(t *testing.T) {
	tun, _, _ := newTestTunnel(60 * time.Millisecond)
	if err := tun.EnsureStarted(context.Background()); err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	conn, _ := tun.Track(c1, nil)
	tun.lastUse.Store(time.Now().Add(-time.Hour).UnixNano())
	if tun.ReapOnce() {
		t.Fatal("tunnel with an active connection was torn down")
	}
	conn.Close()
	conn.Close() // double close releases once
	if tun.Active() != 0 {
		t.Fatalf("active = %d after close, want 0", tun.Active())
	}
	tun.lastUse.Store(time.Now().Add(-time.Second).UnixNano())
	if !tun.ReapOnce() {
		t.Fatal("tunnel was not torn down after its last connection closed")
	}
}

func TestTrackPassesErrors(t *testing.T) {
	tun, _, _ := newTestTunnel(0)
	if _, err := tun.Track(nil, errors.New("dial failed")); err == nil || tun.Active() != 0 {
		t.Fatal("Track swallowed the error or counted a failed dial")
	}
	if _, err := tun.TrackPacket(nil, errors.New("dial failed")); err == nil || tun.Active() != 0 {
		t.Fatal("TrackPacket swallowed the error or counted a failed dial")
	}
}

func TestZeroIdleNeverReaps(t *testing.T) {
	tun, _, _ := newTestTunnel(0)
	if err := tun.EnsureStarted(context.Background()); err != nil {
		t.Fatal(err)
	}
	tun.lastUse.Store(0)
	if tun.ReapOnce() || !tun.Ready() {
		t.Fatal("idle teardown ran with idleTimeout 0")
	}
	if err := tun.Close(); err != nil || tun.Ready() {
		t.Fatal("Close did not tear down")
	}
}
