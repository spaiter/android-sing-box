// wdtt-checkhash — validate VK call hashes for the vpn-bot's managed pool.
// Usage: wdtt-checkhash <hash|link> [more…]  (also accepts comma/space lists)
// Prints one line per hash:  HASH_CHECK|<hash>|<status>|<detail>
// status ∈ ok/dead/captcha/limited/network/error. Exit 0 always (per-hash status
// is in the output); exit 2 on usage error.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	wdtt "github.com/sagernet/sing-box/transport/wdtt"
)

func main() {
	hashes := wdtt.ParseHashes(strings.Join(os.Args[1:], ","))
	if len(hashes) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wdtt-checkhash <vk-call-hash|link> [more…]")
		os.Exit(2)
	}
	for _, r := range wdtt.CheckHashes(context.Background(), "yandex", hashes) {
		fmt.Printf("HASH_CHECK|%s|%s|%s\n", r.Hash, r.Status, r.Detail)
	}
}
