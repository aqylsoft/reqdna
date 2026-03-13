package reqdna

import "time"

// TestFingerprint creates a Fingerprint for testing purposes.
// All fields can be overridden after creation.
//
// Example in user tests:
//
//	func TestBotBlocking(t *testing.T) {
//	    fp := reqdna.TestFingerprint()
//	    fp.BotScore = 0.95  // Simulate bot
//
//	    // Test your handler with this fingerprint
//	}
func TestFingerprint() Fingerprint {
	return Fingerprint{
		Hash: "test-fingerprint-hash-0000000000000000",
		IP: IPInfo{
			Hash:       "test-ip-hash",
			Version:    4,
			IsPrivate:  true,
			IsLoopback: false,
		},
		TLS: TLSInfo{
			Available: false,
		},
		Headers: HeaderInfo{
			Order:            []string{"User-Agent", "Accept"},
			OrderHash:        "test-order-hash",
			Count:            2,
			HasCommonBrowser: true,
			Entropy:          0.2,
		},
		Device: DeviceInfo{
			Type:    DeviceDesktop,
			OS:      "Linux",
			Browser: "TestBrowser",
			Raw:     "TestBrowser/1.0",
		},
		BotScore:    0.0,
		RequestedAt: time.Now(),
	}
}

// TestBotFingerprint creates a Fingerprint that looks like a bot.
//
// Example:
//
//	fp := reqdna.TestBotFingerprint()
//	if !fp.IsBot() {
//	    t.Error("should be detected as bot")
//	}
func TestBotFingerprint() Fingerprint {
	fp := TestFingerprint()
	fp.BotScore = 0.95
	fp.Device.Type = DeviceBot
	fp.Device.Browser = "TestBot"
	fp.Headers.HasCommonBrowser = false
	fp.Headers.Entropy = 0.8
	return fp
}

// TestMobileFingerprint creates a Fingerprint for a mobile device.
func TestMobileFingerprint() Fingerprint {
	fp := TestFingerprint()
	fp.Device.Type = DeviceMobile
	fp.Device.OS = "iOS"
	fp.Device.Browser = "Safari"
	fp.Device.Raw = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1"
	return fp
}
