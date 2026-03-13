package reqdna

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFromRequest_Basic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.RemoteAddr = "192.168.1.1:12345"

	fp := FromRequest(req)

	if fp.Hash == "" {
		t.Error("Hash should not be empty")
	}

	if fp.IP.Hash == "" {
		t.Error("IP hash should not be empty")
	}

	if fp.IP.Version != 4 {
		t.Errorf("Expected IPv4, got %d", fp.IP.Version)
	}

	if fp.Device.OS != "Windows" {
		t.Errorf("Expected Windows, got %s", fp.Device.OS)
	}

	if fp.Device.Browser != "Chrome" {
		t.Errorf("Expected Chrome, got %s", fp.Device.Browser)
	}

	if fp.Headers.Count == 0 {
		t.Error("Headers count should not be 0")
	}
}

func TestFromRequest_Bot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Googlebot/2.1")
	req.RemoteAddr = "66.249.66.1:12345"

	fp := FromRequest(req)

	if fp.Device.Type != DeviceBot {
		t.Errorf("Expected bot device type, got %s", fp.Device.Type)
	}

	if fp.BotScore < 0.7 {
		t.Errorf("Expected high bot score, got %.2f", fp.BotScore)
	}

	if !fp.IsBot() {
		t.Error("IsBot() should return true")
	}
}

func TestFromRequest_Curl(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "10.0.0.1:12345"

	fp := FromRequest(req)

	if fp.Device.Type != DeviceBot {
		t.Errorf("curl should be detected as bot, got %s", fp.Device.Type)
	}

	if fp.Device.Browser != "cURL" {
		t.Errorf("Expected cURL browser, got %s", fp.Device.Browser)
	}
}

func TestFromRequest_Mobile(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.168.1.1:12345"

	fp := FromRequest(req)

	if fp.Device.Type != DeviceMobile {
		t.Errorf("Expected mobile device type, got %s", fp.Device.Type)
	}

	if fp.Device.OS != "iOS" {
		t.Errorf("Expected iOS, got %s", fp.Device.OS)
	}
}

func TestWithRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	fp1 := FromRequest(req)
	fp2 := FromRequest(req, WithRealIP("8.8.8.8"))

	if fp1.IP.Hash == fp2.IP.Hash {
		t.Error("IP hashes should be different with WithRealIP")
	}
}

func TestWithHashSalt(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	fp1 := FromRequest(req, WithHashSalt("salt1"))
	fp2 := FromRequest(req, WithHashSalt("salt2"))

	if fp1.IP.Hash == fp2.IP.Hash {
		t.Error("Different salts should produce different IP hashes")
	}
}

func TestMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp, ok := Get(r.Context())
		if !ok {
			t.Error("Fingerprint not found in context")
			return
		}
		if fp.Hash == "" {
			t.Error("Hash should not be empty")
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Test/1.0")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestStableHash(t *testing.T) {
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 Test")
	req1.RemoteAddr = "192.168.1.1:12345"

	req2 := httptest.NewRequest(http.MethodGet, "/different-path", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 Test")
	req2.RemoteAddr = "192.168.1.1:54321" // Different port

	fp1 := FromRequest(req1, WithHashSalt("test"))
	fp2 := FromRequest(req2, WithHashSalt("test"))

	if fp1.Hash != fp2.Hash {
		t.Error("Same client should produce same hash regardless of path/port")
	}
}

func BenchmarkFromRequest(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	req.RemoteAddr = "192.168.1.1:12345"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = FromRequest(req)
	}
}

func BenchmarkFromRequest_WithOptions(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	req.RemoteAddr = "192.168.1.1:12345"

	opts := []Option{
		WithHashSalt("benchmark-salt"),
		WithRealIP("10.0.0.1"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = FromRequest(req, opts...)
	}
}
