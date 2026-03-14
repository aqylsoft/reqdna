package reqdna

import (
	"encoding/json"
	"time"
)

// BotSignal represents a single detection signal that contributed to BotScore.
type BotSignal struct {
	// Name identifies the signal (e.g. "missing_user_agent", "suspicious_ua").
	Name string `json:"name"`

	// Weight is the contribution of this signal to the total BotScore.
	Weight float64 `json:"weight"`
}

// BotScoreBreakdown provides transparency into how BotScore was calculated.
// Each entry in Signals is a signal that fired and its weight contribution.
// The final BotScore equals sum(Signals[].Weight) capped at 1.0.
//
// Use this for audit logging and compliance explanations when you need to
// justify why a request was flagged (e.g. to a compliance officer).
type BotScoreBreakdown struct {
	Signals []BotSignal `json:"signals"`
}

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
	// Thresholds: >= 0.7 → IsBot(), >= 0.4 → IsSuspicious().
	BotScore float64 `json:"bot_score"`

	// BotScoreBreakdown lists every signal that contributed to BotScore
	// along with its individual weight. Use this for compliance explanations.
	BotScoreBreakdown BotScoreBreakdown `json:"bot_score_breakdown"`

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
