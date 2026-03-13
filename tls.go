package reqdna

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
)

// TLSInfo contains TLS connection fingerprint data.
type TLSInfo struct {
	// Version is the TLS version (e.g., 0x0303 for TLS 1.2).
	Version uint16 `json:"version"`

	// VersionName is human-readable version name.
	VersionName string `json:"version_name"`

	// CipherSuite is the negotiated cipher suite.
	CipherSuite uint16 `json:"cipher_suite"`

	// CipherSuiteName is human-readable cipher suite name.
	CipherSuiteName string `json:"cipher_suite_name"`

	// ServerName is the SNI value (if available).
	ServerName string `json:"server_name,omitempty"`

	// Hash is a JA3-style fingerprint hash.
	Hash string `json:"hash"`

	// Available indicates if TLS info was available.
	Available bool `json:"available"`
}

// TLS version constants for readability.
const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// analyzeTLS extracts TLS fingerprint from connection state.
func analyzeTLS(state *tls.ConnectionState) TLSInfo {
	if state == nil {
		return TLSInfo{Available: false}
	}

	return TLSInfo{
		Version:         state.Version,
		VersionName:     tlsVersionName(state.Version),
		CipherSuite:     state.CipherSuite,
		CipherSuiteName: tls.CipherSuiteName(state.CipherSuite),
		ServerName:      state.ServerName,
		Hash:            computeTLSHash(state),
		Available:       true,
	}
}

// computeTLSHash creates a JA3-style hash from TLS parameters.
// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// We use a simplified version since Go doesn't expose all ClientHello details.
func computeTLSHash(state *tls.ConnectionState) string {
	// Build a fingerprint string from available data
	fp := fmt.Sprintf("%d,%d,%s",
		state.Version,
		state.CipherSuite,
		state.ServerName,
	)

	h := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(h[:])[:12]
}

func tlsVersionName(v uint16) string {
	switch v {
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}
