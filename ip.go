package reqdna

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
)

// IPInfo contains IP address metadata.
type IPInfo struct {
	// Hash is the hashed IP address (privacy-preserving).
	Hash string `json:"hash"`

	// Version is 4 or 6.
	Version int `json:"version"`

	// IsPrivate indicates if IP is from private range.
	IsPrivate bool `json:"is_private"`

	// IsLoopback indicates if IP is loopback.
	IsLoopback bool `json:"is_loopback"`
}

// extractIP extracts IP from RemoteAddr or X-Forwarded-For/X-Real-IP headers.
func extractIP(remoteAddr string, realIP string) string {
	// If realIP is provided (from reverse proxy), use it
	if realIP != "" {
		// X-Forwarded-For can contain multiple IPs, take the first
		if idx := strings.Index(realIP, ","); idx != -1 {
			return strings.TrimSpace(realIP[:idx])
		}
		return strings.TrimSpace(realIP)
	}

	// Extract IP from host:port format
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Maybe it's just an IP without port
		return remoteAddr
	}
	return host
}

// analyzeIP creates IPInfo from an IP string.
func analyzeIP(ipStr string, salt string) IPInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return IPInfo{
			Hash:    hashString(ipStr, salt),
			Version: 0,
		}
	}

	version := 4
	if ip.To4() == nil {
		version = 6
	}

	return IPInfo{
		Hash:       hashIP(ip, salt),
		Version:    version,
		IsPrivate:  ip.IsPrivate(),
		IsLoopback: ip.IsLoopback(),
	}
}

// hashIP creates a salted hash of the IP address.
func hashIP(ip net.IP, salt string) string {
	return hashString(ip.String(), salt)
}

// hashString creates a salted SHA256 hash.
func hashString(s string, salt string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))[:16] // First 16 chars for brevity
}
