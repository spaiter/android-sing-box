package wdtt

// library.go — clean embeddable API over the qWDTT client machinery, for use as
// a native sing-box `wdtt` outbound. Runs the local UDP <-> VK-TURN bridge (the
// same Dispatcher/WorkerGroup pipeline as the CLI, minus flags/stdin), fetches
// the WireGuard config from the server via GETCONF, and hands back the local
// port so the outbound can run an embedded WireGuard device pointed at it.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ClientConfig configures one WG-over-VK client bridge.
type ClientConfig struct {
	PeerAddr string   // wdtt server addr:port (DTLS)
	Password string   // WRAP key material + GETCONF auth
	Hashes   []string // VK call hashes (required, even in anonymous mode)
	DeviceID string   // device identifier (default "sing-box")
	DNS      string   // VK resolver, default "yandex"
	Obfs     string   // "audio" (default) or "video"
	Workers  int      // TURN worker count (default 24)
}

// ClientHandle is a running bridge. WGConfig holds the WireGuard config the
// server returned via GETCONF (client privkey / server pubkey / address).
type ClientHandle struct {
	LocalPort string
	WGConfig  string
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// Close stops the bridge and waits for its workers to exit.
func (h *ClientHandle) Close() {
	if h.cancel != nil {
		h.cancel()
	}
	h.wg.Wait()
}

// RunClientBridge starts the VK-TURN bridge, waits (up to ~40s) for the server
// WireGuard config via GETCONF, and returns a handle. The embedded WG device
// should dial 127.0.0.1:<LocalPort>.
func RunClientBridge(parent context.Context, cfg ClientConfig) (*ClientHandle, error) {
	if cfg.PeerAddr == "" {
		return nil, fmt.Errorf("wdtt: PeerAddr required")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("wdtt: Password required")
	}
	if len(cfg.Hashes) == 0 {
		return nil, fmt.Errorf("wdtt: at least one VK hash required")
	}
	if cfg.DeviceID == "" {
		cfg.DeviceID = "sing-box"
	}
	if cfg.DNS == "" {
		cfg.DNS = "yandex"
	}
	if cfg.Obfs == "" {
		cfg.Obfs = "audio"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 24
	}

	setupGlobalResolver(cfg.DNS)
	setCaptchaMode("auto")
	setVkAuthMode("anonymous")
	setVkAnonPath("vkcalls")

	peer, err := net.ResolveUDPAddr("udp", cfg.PeerAddr)
	if err != nil {
		return nil, fmt.Errorf("wdtt: resolve peer %q: %w", cfg.PeerAddr, err)
	}
	wrapKey, err := deriveWrapKey(cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("wdtt: derive wrap key: %w", err)
	}

	numW := cfg.Workers
	if numW > 108 {
		numW = 108
	}
	if numW < workersPerGroup {
		numW = workersPerGroup
	}
	numW = (numW / workersPerGroup) * workersPerGroup

	tp := &TurnParams{
		Hashes:   cfg.Hashes,
		WrapKey:  wrapKey,
		ObfsMode: normalizeObfsMode(cfg.Obfs),
	}

	localConn, err := listenUDP("127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("wdtt: local listener: %w", err)
	}
	if uc, ok := localConn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(socketBufSize)
		_ = uc.SetWriteBuffer(socketBufSize)
	}
	_, localPort, _ := net.SplitHostPort(localConn.LocalAddr().String())

	ctx, cancel := context.WithCancel(parent)
	context.AfterFunc(ctx, func() { _ = localConn.Close() })

	h := &ClientHandle{LocalPort: localPort, cancel: cancel}

	stats := NewStats()
	shutdownCh := make(chan struct{})
	go func() { <-ctx.Done(); close(shutdownCh) }()
	go stats.RunLoop(shutdownCh)

	disp := NewDispatcher(ctx, localConn, stats)

	configCh := make(chan string, 1)

	numGroups := (numW + workersPerGroup - 1) / workersPerGroup
	workerIDCounter := 1
	var prevWaitReady <-chan struct{}
	for g := 0; g < numGroups; g++ {
		isFirst := g == 0
		var myWaitReady <-chan struct{}
		var mySignalReady chan<- struct{}
		if g > 0 {
			myWaitReady = prevWaitReady
		}
		if g < numGroups-1 {
			ch := make(chan struct{})
			mySignalReady = ch
			prevWaitReady = ch
		}
		startIdx := g * workersPerGroup
		endIdx := startIdx + workersPerGroup
		if endIdx > numW {
			endIdx = numW
		}
		groupSize := endIdx - startIdx
		if groupSize <= 0 {
			continue
		}
		ids := make([]int, groupSize)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}
		var cc chan<- string
		if isFirst {
			cc = configCh
		}
		var pauseFlag int32
		h.wg.Add(1)
		go func(gID int, first bool, configChan chan<- string, wIds []int, startHash int, waitR <-chan struct{}, sigR chan<- struct{}) {
			defer h.wg.Done()
			WorkerGroup(ctx, gID, startHash, tp, peer, disp, localPort,
				first, configChan, wIds, &pauseFlag, cfg.DeviceID, cfg.Password, stats, waitR, sigR)
		}(g+1, isFirst, cc, ids, g, myWaitReady, mySignalReady)
	}

	h.wg.Add(1)
	go func() { defer h.wg.Done(); disp.Shutdown() }()

	// wait for the WireGuard config from GETCONF
	select {
	case raw := <-configCh:
		if raw == "" {
			cancel()
			return nil, fmt.Errorf("wdtt: empty WireGuard config from server")
		}
		h.WGConfig = ensureMTU(raw)
	case <-time.After(45 * time.Second):
		cancel()
		return nil, fmt.Errorf("wdtt: timeout waiting for server WireGuard config (GETCONF)")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return h, nil
}

func ensureMTU(conf string) string {
	if strings.Contains(conf, "MTU =") {
		return conf
	}
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		out = append(out, line)
		if strings.TrimSpace(line) == "[Interface]" {
			out = append(out, "MTU = 1280")
		}
	}
	return strings.Join(out, "\n")
}
