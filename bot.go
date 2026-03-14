package reqdna

import (
	"net/http"
	"strings"
)

// calculateBotScore computes a bot probability score (0.0 - 1.0) and returns
// a breakdown of every signal that contributed to the score.
//
// Signal weights are stable within a minor version — see CHANGELOG.md for the
// full stability contract.
func calculateBotScore(r *http.Request, device DeviceInfo, headers HeaderInfo, tlsInfo TLSInfo) (float64, BotScoreBreakdown) {
	var score float64
	var fired []BotSignal

	add := func(name string, weight float64) {
		score += weight
		fired = append(fired, BotSignal{Name: name, Weight: weight})
	}

	// Signal 1: Device already detected as bot (weight: 0.9)
	if device.Type == DeviceBot {
		add("device_type_bot", 0.9)
	}

	// Signal 2: Header-based signals (weights vary, see HeaderSignals)
	for name, weight := range HeaderSignals(r.Header) {
		add(name, weight)
	}

	// Signal 3: No TLS in production — weighted low, local dev often lacks TLS (weight: 0.1)
	if !tlsInfo.Available && !isLocalRequest(r) {
		add("no_tls_production", 0.1)
	}

	// Signal 4: Outdated TLS version < 1.2 (weight: 0.3)
	if tlsInfo.Available && tlsInfo.Version < VersionTLS12 {
		add("outdated_tls", 0.3)
	}

	// Signal 5: High header entropy — too many non-browser headers (weight: 0.2)
	if headers.Entropy > 0.7 {
		add("high_header_entropy", 0.2)
	}

	// Signal 6: Missing common browser headers — fewer than 4 standard headers (weight: 0.3)
	if !headers.HasCommonBrowser {
		add("missing_common_browser_headers", 0.3)
	}

	// Signal 7: Suspicious User-Agent patterns (weight: 0.4)
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if hasSuspiciousUA(ua) {
		add("suspicious_ua", 0.4)
	}

	if len(fired) == 0 {
		return 0.0, BotScoreBreakdown{}
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score, BotScoreBreakdown{Signals: fired}
}

func isLocalRequest(r *http.Request) bool {
	host := r.Host
	return strings.HasPrefix(host, "localhost") ||
		strings.HasPrefix(host, "127.0.0.1") ||
		strings.HasPrefix(host, "[::1]")
}

func hasSuspiciousUA(ua string) bool {
	suspicious := []string{
		// Empty or very short
		"",
		// Generic/automated
		"mozilla/5.0",   // Just the prefix, nothing else
		"mozilla/4.0",   // Very old
		"java/",         // Java HTTP clients
		"python-urllib", // Python default
		// Known automation tools
		"phantomjs",
		"headlesschrome",
		"puppeteer",
		"playwright",
		"selenium",
		"webdriver",
	}

	// Check for exact match with very short UAs
	if len(ua) < 10 {
		return true
	}

	for _, s := range suspicious {
		if s != "" && strings.Contains(ua, s) {
			// Special case: full Mozilla string is fine
			if s == "mozilla/5.0" && len(ua) > 20 {
				continue
			}
			return true
		}
	}

	return false
}
