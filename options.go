package reqdna

import (
	"crypto/tls"
)

// Option configures fingerprint extraction.
type Option func(*config)

// config holds all configuration options.
type config struct {
	tlsState *tls.ConnectionState
	realIP   string
	salt     string
}

// defaultConfig returns the default configuration.
func defaultConfig() *config {
	return &config{
		salt: "reqdna", // Default salt for IP hashing
	}
}

// WithTLS provides TLS connection state for fingerprinting.
// Use this when you have access to the raw TLS connection.
//
// Example:
//
//	if r.TLS != nil {
//	    fp := reqdna.FromRequest(r, reqdna.WithTLS(r.TLS))
//	}
func WithTLS(state *tls.ConnectionState) Option {
	return func(c *config) {
		c.tlsState = state
	}
}

// WithRealIP overrides the IP detection with a known real IP.
// Use this when behind a reverse proxy that sets X-Forwarded-For or X-Real-IP.
//
// Example:
//
//	realIP := r.Header.Get("X-Real-IP")
//	fp := reqdna.FromRequest(r, reqdna.WithRealIP(realIP))
func WithRealIP(ip string) Option {
	return func(c *config) {
		c.realIP = ip
	}
}

// WithHashSalt sets a custom salt for IP hashing.
// Use a unique salt per application for privacy.
//
// Example:
//
//	fp := reqdna.FromRequest(r, reqdna.WithHashSalt(os.Getenv("REQDNA_SALT")))
func WithHashSalt(salt string) Option {
	return func(c *config) {
		if salt != "" {
			c.salt = salt
		}
	}
}

// WithTrustedProxies configures trusted proxy detection.
// Headers like X-Forwarded-For will only be trusted from these sources.
// TODO: Implement proxy trust chain validation
// func WithTrustedProxies(cidrs ...string) Option {
// 	return func(c *config) {
// 		// Parse CIDRs and store for validation
// 	}
// }
