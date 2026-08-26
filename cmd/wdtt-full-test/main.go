// wdtt-full-test — full server-side WDTT data-path test (bridge + WG device +
// HTTPS through the tunnel to 1.1.1.1). env: PEER PASS HASH OBFS MTU
package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	wdttproto "github.com/sagernet/sing-box/protocol/wdtt"
	wdtt "github.com/sagernet/sing-box/transport/wdtt"
)

func main() {
	log.SetFlags(log.Ltime)
	peer, pass, hash, obfs := os.Getenv("PEER"), os.Getenv("PASS"), os.Getenv("HASH"), os.Getenv("OBFS")
	if obfs == "" {
		obfs = "rtpopus3"
	}
	mtu := uint32(1000)
	if v := os.Getenv("MTU"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			mtu = uint32(n)
		}
	}
	if peer == "" || pass == "" || hash == "" {
		log.Fatal("need PEER PASS HASH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	log.Printf("=== full-path test peer=%s obfs=%s mtu=%d ===", peer, obfs, mtu)
	res, err := wdttproto.RunFullPathTest(ctx, wdtt.ClientConfig{
		PeerAddr: peer, Password: pass, Hashes: []string{hash}, Obfs: obfs, Workers: 24,
	}, mtu, "1.1.1.1")
	if err != nil {
		log.Fatalf("FAIL: %v", err)
	}
	log.Printf("SUCCESS:\n%s", res)
}
