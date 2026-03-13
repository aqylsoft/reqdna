package reqdna

import (
	"encoding/json"
	"time"
)

// Fingerprint contains all extracted metadata and the stable hash.
type Fingerprint struct {
	// Hash is a stable SHA256 fingerprint of the request.
	Hash string `json:"hash"`

	// IP contains IP address metadata (hashed by default for privacy).
	IP IPInfo `json:"ip"`

	// TLS contains TLS connection fingerprint (JA3-style).
	TLS TLSInfo `json:"tls"`

	// Headers contains header analysis data.
	Headers HeaderInfo `json:"headers"`

	// Device contains parsed device/browser information.
	Device DeviceInfo `json:"device"`

	// BotScore is a probability (0.0 - 1.0) that request is from a bot.
	BotScore float64 `json:"bot_score"`

	// RequestedAt is when the fingerprint was created.
	RequestedAt time.Time `json:"requested_at"`
}

// String returns JSON representation of the fingerprint.
func (f Fingerprint) String() string {
	b, _ := json.Marshal(f)
	return string(b)
}

// JSON returns indented JSON representation.
func (f Fingerprint) JSON() string {
	b, _ := json.MarshalIndent(f, "", "  ")
	return string(b)
}

// IsBot returns true if BotScore >= 0.7.
func (f Fingerprint) IsBot() bool {
	return f.BotScore >= 0.7
}

// IsSuspicious returns true if BotScore >= 0.4.
func (f Fingerprint) IsSuspicious() bool {
	return f.BotScore >= 0.4
}
