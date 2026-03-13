package reqdna

import (
	"strings"
)

// DeviceType represents the type of device.
type DeviceType string

const (
	DeviceDesktop DeviceType = "desktop"
	DeviceMobile  DeviceType = "mobile"
	DeviceTablet  DeviceType = "tablet"
	DeviceBot     DeviceType = "bot"
	DeviceUnknown DeviceType = "unknown"
)

// DeviceInfo contains parsed device/browser information.
type DeviceInfo struct {
	// Type is the device type (desktop, mobile, tablet, bot, unknown).
	Type DeviceType `json:"type"`

	// OS is the detected operating system.
	OS string `json:"os"`

	// Browser is the detected browser name.
	Browser string `json:"browser"`

	// BrowserVersion is the browser version (if detected).
	BrowserVersion string `json:"browser_version,omitempty"`

	// Raw is the original User-Agent string.
	Raw string `json:"raw"`
}

// analyzeDevice parses User-Agent and extracts device information.
// Simple parser without external dependencies.
func analyzeDevice(userAgent string) DeviceInfo {
	ua := strings.ToLower(userAgent)

	info := DeviceInfo{
		Raw:  userAgent,
		Type: DeviceUnknown,
	}

	// Detect bots first
	if isBot(ua) {
		info.Type = DeviceBot
		info.Browser = detectBotName(ua)
		return info
	}

	// Detect OS
	info.OS = detectOS(ua)

	// Detect browser
	info.Browser, info.BrowserVersion = detectBrowser(userAgent)

	// Detect device type
	info.Type = detectDeviceType(ua)

	return info
}

func isBot(ua string) bool {
	botSignals := []string{
		"bot", "crawler", "spider", "scraper",
		"curl", "wget", "httpie", "python-requests",
		"go-http-client", "java/", "libwww",
		"headless", "phantom", "selenium",
		"googlebot", "bingbot", "yandexbot",
		"slurp", "duckduckbot", "baiduspider",
		"facebookexternalhit", "twitterbot",
		"linkedinbot", "whatsapp", "telegrambot",
	}

	for _, signal := range botSignals {
		if strings.Contains(ua, signal) {
			return true
		}
	}
	return false
}

func detectBotName(ua string) string {
	bots := map[string]string{
		"googlebot":           "Googlebot",
		"bingbot":             "Bingbot",
		"yandexbot":           "YandexBot",
		"duckduckbot":         "DuckDuckBot",
		"baiduspider":         "Baiduspider",
		"facebookexternalhit": "Facebook",
		"twitterbot":          "Twitter",
		"linkedinbot":         "LinkedIn",
		"telegrambot":         "Telegram",
		"whatsapp":            "WhatsApp",
		"curl":                "cURL",
		"wget":                "Wget",
		"python-requests":     "Python Requests",
		"go-http-client":      "Go HTTP Client",
		"httpie":              "HTTPie",
	}

	for signal, name := range bots {
		if strings.Contains(ua, signal) {
			return name
		}
	}
	return "Unknown Bot"
}

func detectOS(ua string) string {
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS" // Check iOS BEFORE macOS (iOS UA contains "Mac OS X")
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh"):
		return "macOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "linux"):
		return "Linux"
	case strings.Contains(ua, "cros"):
		return "Chrome OS"
	default:
		return "Unknown"
	}
}

func detectBrowser(ua string) (name, version string) {
	uaLower := strings.ToLower(ua)

	// Order matters: check specific browsers before generic ones
	browsers := []struct {
		signal string
		name   string
	}{
		{"edg/", "Edge"},
		{"opr/", "Opera"},
		{"opera", "Opera"},
		{"firefox/", "Firefox"},
		{"chrome/", "Chrome"},
		{"safari/", "Safari"},
		{"msie", "Internet Explorer"},
		{"trident/", "Internet Explorer"},
	}

	for _, b := range browsers {
		if strings.Contains(uaLower, b.signal) {
			return b.name, extractVersion(ua, b.signal)
		}
	}

	return "Unknown", ""
}

func extractVersion(ua, signal string) string {
	idx := strings.Index(strings.ToLower(ua), signal)
	if idx == -1 {
		return ""
	}

	start := idx + len(signal)
	if start >= len(ua) {
		return ""
	}

	// Extract version number
	var version strings.Builder
	for i := start; i < len(ua); i++ {
		c := ua[i]
		if (c >= '0' && c <= '9') || c == '.' {
			version.WriteByte(c)
		} else {
			break
		}
	}

	return version.String()
}

func detectDeviceType(ua string) DeviceType {
	switch {
	case strings.Contains(ua, "mobile"):
		return DeviceMobile
	case strings.Contains(ua, "iphone"):
		return DeviceMobile
	case strings.Contains(ua, "android") && !strings.Contains(ua, "tablet"):
		if strings.Contains(ua, "mobile") {
			return DeviceMobile
		}
		return DeviceTablet
	case strings.Contains(ua, "ipad"):
		return DeviceTablet
	case strings.Contains(ua, "tablet"):
		return DeviceTablet
	default:
		return DeviceDesktop
	}
}
