package reqdna

import (
	"net/http"
	"strings"
)

// calculateBotScore computes a bot probability score (0.0 - 1.0).
// Uses multiple signals to detect automated requests.
func calculateBotScore(r *http.Request, device DeviceInfo, headers HeaderInfo, tlsInfo TLSInfo) float64 {
	var score float64
	var signals int

	// Signal 1: Device already detected as bot
	if device.Type == DeviceBot {
		score += 0.9
		signals++
	}

	// Signal 2: Header-based signals using range over func
	for _, weight := range HeaderSignals(r.Header) {
		score += weight
		signals++
	}

	// Signal 3: No TLS in production (suspicious)
	// This is weighted lower since local dev often lacks TLS
	if !tlsInfo.Available && !isLocalRequest(r) {
		score += 0.1
		signals++
	}

	// Signal 4: Outdated TLS version
	if tlsInfo.Available && tlsInfo.Version < VersionTLS12 {
		score += 0.3
		signals++
	}

	// Signal 5: Low header entropy (too uniform)
	if headers.Entropy > 0.7 {
		score += 0.2
		signals++
	}

	// Signal 6: Missing common browser headers
	if !headers.HasCommonBrowser {
		score += 0.3
		signals++
	}

	// Signal 7: Suspicious User-Agent patterns
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if hasSuspiciousUA(ua) {
		score += 0.4
		signals++
	}

	// Normalize score to 0.0 - 1.0 range
	if signals == 0 {
		return 0.0
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
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
