package reqdna

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
)

// JA3Info contains full JA3 TLS fingerprint data.
// JA3 is a method for creating SSL/TLS client fingerprints.
// See: https://github.com/salesforce/ja3
type JA3Info struct {
	// Version is the TLS version from ClientHello.
	Version uint16 `json:"version"`

	// CipherSuites is the list of cipher suites offered by client.
	CipherSuites []uint16 `json:"cipher_suites"`

	// Extensions is the list of TLS extensions.
	Extensions []uint16 `json:"extensions"`

	// Curves is the list of supported elliptic curves.
	Curves []uint16 `json:"curves"`

	// PointFormats is the list of EC point formats.
	PointFormats []uint8 `json:"point_formats"`

	// String is the raw JA3 string before hashing.
	// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
	String string `json:"ja3_string"`

	// Hash is the MD5 hash of the JA3 string.
	Hash string `json:"ja3_hash"`
}

// ComputeJA3 creates a JA3 fingerprint from ClientHelloInfo.
// Returns nil if hello is nil.
func ComputeJA3(hello *tls.ClientHelloInfo) *JA3Info {
	if hello == nil {
		return nil
	}

	// Get TLS version - use highest supported version
	var version uint16
	if len(hello.SupportedVersions) > 0 {
		version = hello.SupportedVersions[0]
	}

	// Filter GREASE values from cipher suites
	cipherSuites := filterGREASE16(hello.CipherSuites)

	// Filter GREASE values from extensions
	extensions := filterGREASE16(hello.Extensions)

	// Convert curves to uint16 and filter GREASE
	curves := make([]uint16, 0, len(hello.SupportedCurves))
	for _, c := range hello.SupportedCurves {
		if !isGREASE16(uint16(c)) {
			curves = append(curves, uint16(c))
		}
	}

	// Point formats don't have GREASE values
	pointFormats := hello.SupportedPoints

	info := &JA3Info{
		Version:      version,
		CipherSuites: cipherSuites,
		Extensions:   extensions,
		Curves:       curves,
		PointFormats: pointFormats,
	}

	// Build JA3 string
	info.String = buildJA3String(info)

	// Compute MD5 hash
	hash := md5.Sum([]byte(info.String))
	info.Hash = hex.EncodeToString(hash[:])

	return info
}

// buildJA3String creates the JA3 fingerprint string.
// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
func buildJA3String(info *JA3Info) string {
	var b strings.Builder

	// Version
	b.WriteString(strconv.FormatUint(uint64(info.Version), 10))
	b.WriteByte(',')

	// Cipher suites (joined by -)
	b.WriteString(joinUint16(info.CipherSuites, "-"))
	b.WriteByte(',')

	// Extensions (joined by -)
	b.WriteString(joinUint16(info.Extensions, "-"))
	b.WriteByte(',')

	// Elliptic curves (joined by -)
	b.WriteString(joinUint16(info.Curves, "-"))
	b.WriteByte(',')

	// EC point formats (joined by -)
	b.WriteString(joinUint8(info.PointFormats, "-"))

	return b.String()
}

// isGREASE16 checks if a value is a GREASE value.
// GREASE values match pattern 0x?a?a where ? is the same nibble.
// See RFC 8701.
func isGREASE16(v uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	if (v & 0x0f0f) != 0x0a0a {
		return false
	}
	return (v >> 8) == (v & 0xff)
}

// filterGREASE16 removes GREASE values from a slice.
func filterGREASE16(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE16(v) {
			out = append(out, v)
		}
	}
	return out
}

// joinUint16 joins uint16 slice with separator.
func joinUint16(vals []uint16, sep string) string {
	if len(vals) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range vals {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// joinUint8 joins uint8 slice with separator.
func joinUint8(vals []uint8, sep string) string {
	if len(vals) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range vals {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// ClientHelloStore stores ClientHello data for each connection.
// Use this with WrapTLSConfig to capture ClientHello during TLS handshake.
type ClientHelloStore struct {
	mu    sync.RWMutex
	store map[string]*tls.ClientHelloInfo
}

// NewClientHelloStore creates a new ClientHelloStore.
func NewClientHelloStore() *ClientHelloStore {
	return &ClientHelloStore{
		store: make(map[string]*tls.ClientHelloInfo),
	}
}

// Put stores ClientHello for a remote address.
func (s *ClientHelloStore) Put(remoteAddr string, hello *tls.ClientHelloInfo) {
	s.mu.Lock()
	s.store[remoteAddr] = hello
	s.mu.Unlock()
}

// Get retrieves ClientHello for a remote address.
func (s *ClientHelloStore) Get(remoteAddr string) *tls.ClientHelloInfo {
	s.mu.RLock()
	hello := s.store[remoteAddr]
	s.mu.RUnlock()
	return hello
}

// Delete removes ClientHello for a remote address.
// Call this after the request is processed to prevent memory leaks.
func (s *ClientHelloStore) Delete(remoteAddr string) {
	s.mu.Lock()
	delete(s.store, remoteAddr)
	s.mu.Unlock()
}

// Len returns the number of stored entries.
func (s *ClientHelloStore) Len() int {
	s.mu.RLock()
	n := len(s.store)
	s.mu.RUnlock()
	return n
}

// WrapTLSConfig wraps a tls.Config to capture ClientHello during handshake.
// The captured ClientHello is stored in the provided store, keyed by remote address.
//
// Example:
//
//	store := reqdna.NewClientHelloStore()
//	tlsConfig := reqdna.WrapTLSConfig(&tls.Config{
//	    Certificates: []tls.Certificate{cert},
//	}, store)
//
//	server := &http.Server{
//	    TLSConfig: tlsConfig,
//	}
func WrapTLSConfig(cfg *tls.Config, store *ClientHelloStore) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}

	// Clone to avoid modifying the original
	wrapped := cfg.Clone()

	// Save original callback
	origGetConfigForClient := cfg.GetConfigForClient

	// Set our callback that captures ClientHello
	wrapped.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Store ClientHello by remote address
		if hello.Conn != nil {
			store.Put(hello.Conn.RemoteAddr().String(), hello)
		}

		// Call original callback if it exists
		if origGetConfigForClient != nil {
			return origGetConfigForClient(hello)
		}
		return nil, nil
	}

	return wrapped
}
