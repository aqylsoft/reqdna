package reqdna

import (
	"crypto/sha256"
	"encoding/hex"
	"iter"
	"math"
	"net/http"
	"strings"
)

// HeaderInfo contains header analysis data.
type HeaderInfo struct {
	// Order is the sequence of header names (key fingerprinting signal).
	Order []string `json:"order"`

	// OrderHash is a hash of the header order.
	OrderHash string `json:"order_hash"`

	// Count is the total number of headers.
	Count int `json:"count"`

	// HasCommonBrowser indicates presence of typical browser headers.
	HasCommonBrowser bool `json:"has_common_browser"`

	// Entropy measures unusualness of header set (0.0 = very common).
	Entropy float64 `json:"entropy"`
}

// Common browser headers that real browsers typically send.
var commonBrowserHeaders = map[string]struct{}{
	"Accept":                    {},
	"Accept-Language":          {},
	"Accept-Encoding":          {},
	"Connection":               {},
	"User-Agent":               {},
	"Sec-Fetch-Dest":           {},
	"Sec-Fetch-Mode":           {},
	"Sec-Fetch-Site":           {},
	"Sec-Ch-Ua":                {},
	"Sec-Ch-Ua-Mobile":         {},
	"Sec-Ch-Ua-Platform":       {},
	"Upgrade-Insecure-Requests": {},
}

// analyzeHeaders extracts header information from the request.
func analyzeHeaders(h http.Header) HeaderInfo {
	order := extractHeaderOrder(h)

	return HeaderInfo{
		Order:            order,
		OrderHash:        hashHeaderOrder(order),
		Count:            len(h),
		HasCommonBrowser: hasCommonBrowserHeaders(h),
		Entropy:          calculateHeaderEntropy(h),
	}
}

// extractHeaderOrder returns headers in their original order.
// Note: Go's http.Header doesn't preserve order, but we work with what we have.
func extractHeaderOrder(h http.Header) []string {
	order := make([]string, 0, len(h))
	for name := range h {
		order = append(order, name)
	}
	return order
}

// HeaderSignals returns an iterator over header-based bot signals.
// Uses Go 1.23+ range over func feature.
func HeaderSignals(h http.Header) iter.Seq2[string, float64] {
	return func(yield func(string, float64) bool) {
		// Missing User-Agent is highly suspicious
		if h.Get("User-Agent") == "" {
			if !yield("missing_user_agent", 0.8) {
				return
			}
		}

		// Missing Accept header
		if h.Get("Accept") == "" {
			if !yield("missing_accept", 0.3) {
				return
			}
		}

		// Missing Accept-Language (browsers always send this)
		if h.Get("Accept-Language") == "" {
			if !yield("missing_accept_language", 0.4) {
				return
			}
		}

		// Missing Accept-Encoding
		if h.Get("Accept-Encoding") == "" {
			if !yield("missing_accept_encoding", 0.2) {
				return
			}
		}

		// Very few headers (bots often send minimal headers)
		if len(h) < 3 {
			if !yield("too_few_headers", 0.5) {
				return
			}
		}

		// Unusual header present
		for name := range h {
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "x-") && !isCommonXHeader(lower) {
				if !yield("unusual_x_header", 0.1) {
					return
				}
				break
			}
		}
	}
}

func isCommonXHeader(name string) bool {
	common := []string{
		"x-forwarded-for",
		"x-forwarded-proto",
		"x-real-ip",
		"x-requested-with",
		"x-csrf-token",
	}
	for _, c := range common {
		if name == c {
			return true
		}
	}
	return false
}

func hashHeaderOrder(order []string) string {
	h := sha256.New()
	for _, name := range order {
		h.Write([]byte(name))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func hasCommonBrowserHeaders(h http.Header) bool {
	count := 0
	for name := range h {
		if _, ok := commonBrowserHeaders[name]; ok {
			count++
		}
	}
	// Real browsers typically have at least 4 common headers
	return count >= 4
}

func calculateHeaderEntropy(h http.Header) float64 {
	if len(h) == 0 {
		return 1.0 // Maximum entropy for no headers
	}

	// Count common vs uncommon headers
	commonCount := 0
	for name := range h {
		if _, ok := commonBrowserHeaders[name]; ok {
			commonCount++
		}
	}

	ratio := float64(commonCount) / float64(len(h))

	// Entropy: 0 = all common, 1 = all unusual
	entropy := 1.0 - ratio

	// Normalize to 0-1 range with some smoothing
	return math.Round(entropy*100) / 100
}
