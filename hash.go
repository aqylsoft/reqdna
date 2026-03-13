package reqdna

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// generateStableHash creates a stable fingerprint hash from all components.
// The hash is designed to be stable across requests from the same client.
func generateStableHash(ip IPInfo, tls TLSInfo, headers HeaderInfo, device DeviceInfo) string {
	h := sha256.New()

	// Include IP hash (already privacy-preserving)
	h.Write([]byte(ip.Hash))
	h.Write([]byte{0}) // Separator

	// Include TLS fingerprint if available
	if tls.Available {
		h.Write([]byte(tls.Hash))
	}
	h.Write([]byte{0})

	// Include header order hash (key signal)
	h.Write([]byte(headers.OrderHash))
	h.Write([]byte{0})

	// Include device signature
	deviceSig := fmt.Sprintf("%s:%s:%s", device.Type, device.OS, device.Browser)
	h.Write([]byte(deviceSig))

	return hex.EncodeToString(h.Sum(nil))
}
