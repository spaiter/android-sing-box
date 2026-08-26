// wdtt-bridge-test — run the WG-over-VK client bridge once and print verbose
// logs, to debug the client→VK-TURN→server path from the server itself.
// env: PEER=host:port PASS=<wrap-pass> HASH=<vk-hash> OBFS=rtpopus3
package main

import (
	"context"
	"log"
	"os"
	"time"

	wdtt "github.com/sagernet/sing-box/transport/wdtt"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	peer, pass, hash, obfs := os.Getenv("PEER"), os.Getenv("PASS"), os.Getenv("HASH"), os.Getenv("OBFS")
	if obfs == "" {
		obfs = "rtpopus3"
	}
	if peer == "" || pass == "" || hash == "" {
		log.Fatal("need PEER, PASS, HASH env")
	}
	log.Printf("=== bridge test: peer=%s obfs=%s ===", peer, obfs)
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	h, err := wdtt.RunClientBridge(ctx, wdtt.ClientConfig{
		PeerAddr: peer, Password: pass, Hashes: []string{hash}, Obfs: obfs, Workers: 24,
	})
	if err != nil {
		log.Fatalf("BRIDGE FAILED: %v", err)
	}
	log.Printf("BRIDGE UP: localPort=%s", h.LocalPort)
	log.Printf("WGConfig:\n%s", h.WGConfig)
	// Keep the bridge alive so an external awg interface can run over
	// 127.0.0.1:<localPort> to test the full data path (WG->bridge->TURN->obfs->
	// server->egress). Duration from HOLD env (default 15s).
	hold := 15 * time.Second
	if v := os.Getenv("HOLD"); v != "" {
		if d, e := time.ParseDuration(v); e == nil {
			hold = d
		}
	}
	log.Printf("HOLDING bridge %s (localPort=%s) — set up awg iface now", hold, h.LocalPort)
	time.Sleep(hold)
	h.Close()
}
