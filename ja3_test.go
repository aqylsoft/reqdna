package reqdna

import (
	"crypto/tls"
	"testing"
)

func TestComputeJA3_Nil(t *testing.T) {
	ja3 := ComputeJA3(nil)
	if ja3 != nil {
		t.Error("ComputeJA3(nil) should return nil")
	}
}

func TestComputeJA3_Basic(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b},
		Extensions:        []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13, 18},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
	}

	ja3 := ComputeJA3(hello)

	if ja3 == nil {
		t.Fatal("ComputeJA3 returned nil")
	}

	if ja3.Version != tls.VersionTLS13 {
		t.Errorf("Expected version %d, got %d", tls.VersionTLS13, ja3.Version)
	}

	if len(ja3.CipherSuites) != 5 {
		t.Errorf("Expected 5 cipher suites, got %d", len(ja3.CipherSuites))
	}

	if ja3.String == "" {
		t.Error("JA3 string should not be empty")
	}

	if ja3.Hash == "" {
		t.Error("JA3 hash should not be empty")
	}

	if len(ja3.Hash) != 32 {
		t.Errorf("JA3 hash should be 32 chars (MD5 hex), got %d", len(ja3.Hash))
	}
}

func TestComputeJA3_GREASEFiltering(t *testing.T) {
	// GREASE values should be filtered out
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites: []uint16{
			0x0a0a, // GREASE
			0x1301,
			0x1a1a, // GREASE
			0x1302,
		},
		Extensions: []uint16{
			0x2a2a, // GREASE
			0,
			23,
		},
		SupportedCurves: []tls.CurveID{
			0x3a3a, // GREASE
			tls.X25519,
		},
		SupportedPoints: []uint8{0},
	}

	ja3 := ComputeJA3(hello)

	// Should have filtered out GREASE values
	if len(ja3.CipherSuites) != 2 {
		t.Errorf("Expected 2 cipher suites after GREASE filter, got %d", len(ja3.CipherSuites))
	}

	if len(ja3.Extensions) != 2 {
		t.Errorf("Expected 2 extensions after GREASE filter, got %d", len(ja3.Extensions))
	}

	if len(ja3.Curves) != 1 {
		t.Errorf("Expected 1 curve after GREASE filter, got %d", len(ja3.Curves))
	}
}

func TestIsGREASE(t *testing.T) {
	tests := []struct {
		val      uint16
		isGREASE bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a2a, true},
		{0x3a3a, true},
		{0xfafa, true},
		{0x0000, false},
		{0x1301, false},
		{0x0a0b, false}, // Different nibbles
		{0x0a1a, false}, // Different high bytes
	}

	for _, tt := range tests {
		got := isGREASE16(tt.val)
		if got != tt.isGREASE {
			t.Errorf("isGREASE16(0x%04x) = %v, want %v", tt.val, got, tt.isGREASE)
		}
	}
}

func TestJA3String_Format(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{771}, // TLS 1.2
		CipherSuites:      []uint16{47, 53},
		Extensions:        []uint16{0, 10, 11},
		SupportedCurves:   []tls.CurveID{23, 24},
		SupportedPoints:   []uint8{0},
	}

	ja3 := ComputeJA3(hello)

	// Format: Version,Ciphers,Extensions,Curves,Points
	expected := "771,47-53,0-10-11,23-24,0"
	if ja3.String != expected {
		t.Errorf("JA3 string = %q, want %q", ja3.String, expected)
	}
}

func TestClientHelloStore(t *testing.T) {
	store := NewClientHelloStore()

	if store.Len() != 0 {
		t.Error("New store should be empty")
	}

	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
	}

	store.Put("192.168.1.1:12345", hello)

	if store.Len() != 1 {
		t.Errorf("Store should have 1 entry, got %d", store.Len())
	}

	got := store.Get("192.168.1.1:12345")
	if got != hello {
		t.Error("Get should return stored hello")
	}

	got = store.Get("unknown")
	if got != nil {
		t.Error("Get unknown should return nil")
	}

	store.Delete("192.168.1.1:12345")
	if store.Len() != 0 {
		t.Error("Store should be empty after delete")
	}
}

func TestWrapTLSConfig(t *testing.T) {
	store := NewClientHelloStore()

	original := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	wrapped := WrapTLSConfig(original, store)

	if wrapped.MinVersion != tls.VersionTLS12 {
		t.Error("Wrapped config should preserve original settings")
	}

	if wrapped.GetConfigForClient == nil {
		t.Error("Wrapped config should have GetConfigForClient set")
	}

	// Original should not be modified
	if original.GetConfigForClient != nil {
		t.Error("Original config should not be modified")
	}
}

func TestWrapTLSConfig_Nil(t *testing.T) {
	store := NewClientHelloStore()

	wrapped := WrapTLSConfig(nil, store)

	if wrapped == nil {
		t.Error("WrapTLSConfig(nil) should return non-nil config")
	}

	if wrapped.GetConfigForClient == nil {
		t.Error("Wrapped config should have GetConfigForClient set")
	}
}

func BenchmarkComputeJA3(b *testing.B) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f},
		Extensions:        []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ComputeJA3(hello)
	}
}
