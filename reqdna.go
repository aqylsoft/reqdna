// Package reqdna provides HTTP request fingerprinting for bot detection,
// fraud prevention, and request analysis.
//
// Features:
//   - Stable fingerprint hash across requests from the same client
//   - IP analysis with privacy-preserving hashing
//   - TLS fingerprinting (JA3-style)
//   - Header order analysis (key bot detection signal)
//   - Device/browser detection
//   - Bot probability scoring
//
// Basic usage:
//
//	fp := reqdna.FromRequest(r)
//	fmt.Println(fp.Hash)        // Stable fingerprint
//	fmt.Println(fp.BotScore)    // 0.0 - 1.0
//	fmt.Println(fp.IsBot())     // true if BotScore >= 0.7
//
// With options:
//
//	fp := reqdna.FromRequest(r,
//	    reqdna.WithTLS(r.TLS),
//	    reqdna.WithRealIP(r.Header.Get("X-Real-IP")),
//	    reqdna.WithHashSalt("my-secret-salt"),
//	)
package reqdna

import (
	"net/http"
	"time"
)

// Version is the library version.
const Version = "0.1.0"

// FromRequest extracts a fingerprint from an HTTP request.
// This is the main entry point for the library.
//
// By default:
//   - IP is extracted from RemoteAddr and hashed for privacy
//   - TLS info is extracted from r.TLS if available
//   - All headers are analyzed for fingerprinting
//   - Device type is detected from User-Agent
//   - Bot score is calculated from multiple signals
//
// Use options to customize behavior:
//   - WithTLS: Provide custom TLS state
//   - WithRealIP: Override IP (for reverse proxy setups)
//   - WithHashSalt: Custom salt for IP hashing
func FromRequest(r *http.Request, opts ...Option) Fingerprint {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Extract TLS info
	tlsState := cfg.tlsState
	if tlsState == nil && r.TLS != nil {
		tlsState = r.TLS
	}
	tlsInfo := analyzeTLS(tlsState, cfg.clientHello)

	// Extract and hash IP
	ipStr := extractIP(r.RemoteAddr, cfg.realIP)
	ipInfo := analyzeIP(ipStr, cfg.salt)

	// Analyze headers
	headerInfo := analyzeHeaders(r.Header)

	// Detect device
	deviceInfo := analyzeDevice(r.Header.Get("User-Agent"))

	// Calculate bot score
	botScore := calculateBotScore(r, deviceInfo, headerInfo, tlsInfo)

	// Generate stable hash
	hash := generateStableHash(ipInfo, tlsInfo, headerInfo, deviceInfo)

	return Fingerprint{
		Hash:        hash,
		IP:          ipInfo,
		TLS:         tlsInfo,
		Headers:     headerInfo,
		Device:      deviceInfo,
		BotScore:    botScore,
		RequestedAt: time.Now(),
	}
}
