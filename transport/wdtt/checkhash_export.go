// checkhash_export.go — exported VK-hash validity check, reused by the
// standalone wdtt-checkhash helper (cmd/wdtt-checkhash) that the vpn-bot runs to
// auto-validate its managed VK-hash pool. Wraps the same GetCreds path the live
// client uses, with the CLI's error classification.

package wdtt

import (
	"context"
	"fmt"
	"time"
)

// HashCheckResult is one hash's validity outcome. Status is one of
// ok/dead/captcha/limited/network/error (see classifyHashCheckError).
type HashCheckResult struct {
	Hash   string
	Status string
	Detail string
}

// CheckHashes validates each VK call hash by fetching anonymous TURN creds
// (the same GetCreds call the client makes), classifying the outcome. Safe to
// call from a short-lived process; each hash gets its own 90s timeout.
func CheckHashes(ctx context.Context, dns string, hashes []string) []HashCheckResult {
	if dns == "" {
		dns = "yandex"
	}
	setupGlobalResolver(dns)
	setCaptchaMode("auto")
	setVkAuthMode("anonymous")
	setVkAnonPath("vkcalls")

	results := make([]HashCheckResult, 0, len(hashes))
	for i, h := range hashes {
		cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, _, turnURLs, err := GetCreds(cctx, h, 9000+i)
		cancel()
		status, detail := classifyHashCheckError(err)
		if err == nil {
			detail = fmt.Sprintf("TURN urls=%d", len(turnURLs))
		}
		results = append(results, HashCheckResult{
			Hash:   h,
			Status: status,
			Detail: sanitizeHashCheckMessage(detail),
		})
	}
	return results
}
