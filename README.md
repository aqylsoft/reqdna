# reqdna

HTTP request fingerprinting library for Go 1.26+. Extract stable fingerprints for bot detection, fraud prevention, and request analysis.

## Features

- **Stable fingerprint hash** — consistent across requests from the same client
- **IP analysis** — privacy-preserving hashing by default (GDPR-friendly)
- **TLS fingerprinting** — JA3-style hash from TLS connection
- **Header analysis** — order, entropy, missing standard headers
- **Device detection** — OS, browser, device type from User-Agent
- **Bot scoring** — 0.0-1.0 probability based on multiple signals
- **Testable** — interfaces + test helpers for easy mocking
- **Zero dependencies** — stdlib only

## Install

```bash
go get github.com/aqylsoft/reqdna
```

## Quick Start

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/aqylsoft/reqdna"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fp := reqdna.FromRequest(r)

        fmt.Println("Hash:", fp.Hash[:16])
        fmt.Println("Bot Score:", fp.BotScore)
        fmt.Println("Is Bot:", fp.IsBot())
        fmt.Println("Device:", fp.Device.Type, fp.Device.Browser)
    })

    http.ListenAndServe(":8080", nil)
}
```

## Middleware

```go
mux := http.NewServeMux()
mux.HandleFunc("/", handler)

// Wrap with middleware
wrapped := reqdna.Middleware(mux)
http.ListenAndServe(":8080", wrapped)

func handler(w http.ResponseWriter, r *http.Request) {
    fp, ok := reqdna.Get(r.Context())
    if !ok {
        return
    }

    if fp.IsBot() {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
}
```

## Options

```go
fp := reqdna.FromRequest(r,
    reqdna.WithTLS(r.TLS),                    // Custom TLS state
    reqdna.WithRealIP("10.0.0.1"),            // Override IP (reverse proxy)
    reqdna.WithHashSalt("my-secret-salt"),    // Custom salt for IP hashing
    reqdna.WithClientHello(hello),            // Full JA3 fingerprinting
)
```

## JA3 TLS Fingerprinting

JA3 is a method for creating SSL/TLS client fingerprints. Each browser/client has a unique JA3 hash based on how it negotiates TLS connections. This is very hard to spoof.

### How It Works

JA3 extracts from ClientHello:
- TLS version
- Cipher suites offered
- TLS extensions
- Elliptic curves
- EC point formats

Format: `Version,Ciphers,Extensions,Curves,PointFormats` → MD5 hash

### Setup

```go
package main

import (
    "crypto/tls"
    "net/http"
    "github.com/aqylsoft/reqdna"
)

func main() {
    // 1. Create store to capture ClientHello during TLS handshake
    store := reqdna.NewClientHelloStore()

    // 2. Wrap your TLS config
    tlsConfig := reqdna.WrapTLSConfig(&tls.Config{
        MinVersion: tls.VersionTLS12,
        // ... your certificates
    }, store)

    // 3. Use JA3-aware middleware
    mux := http.NewServeMux()
    mux.HandleFunc("/", handler)

    handler := reqdna.MiddlewareWithJA3(mux, store)

    // 4. Start HTTPS server
    server := &http.Server{
        Addr:      ":443",
        Handler:   handler,
        TLSConfig: tlsConfig,
    }
    server.ListenAndServeTLS("cert.pem", "key.pem")
}

func handler(w http.ResponseWriter, r *http.Request) {
    fp, _ := reqdna.Get(r.Context())

    if fp.TLS.JA3 != nil {
        fmt.Println("JA3 Hash:", fp.TLS.JA3.Hash)
        fmt.Println("JA3 String:", fp.TLS.JA3.String)
    }
}
```

### Example JA3 Hashes

| Client | JA3 Hash |
|--------|----------|
| Chrome | `b32309a26951912be7dba376398abc3b` |
| Firefox | `839bbe3ed07fed922ded5aaf714d6842` |
| curl | `456523fc94726331a4d5a2e1d40b2cd7` |
| Python requests | `3b5074b1b5d032e5620f69f9f700ff0e` |

JA3 fingerprints are stable per client version and very difficult to spoof.

## Fingerprint Structure

```go
type Fingerprint struct {
    Hash        string      // Stable SHA256 fingerprint
    IP          IPInfo      // IP metadata (hashed)
    TLS         TLSInfo     // TLS fingerprint
    Headers     HeaderInfo  // Header analysis
    Device      DeviceInfo  // Device/browser info
    BotScore    float64     // 0.0 - 1.0
    RequestedAt time.Time
}
```

## Bot Detection Signals

The library uses multiple signals to calculate bot probability:

- Missing standard headers (User-Agent, Accept, Accept-Language)
- Low header count
- Known bot User-Agent patterns (Googlebot, curl, wget, etc.)
- Header entropy analysis
- TLS version (outdated versions are suspicious)

## Testing Your Code

The library provides interfaces and helpers for easy mocking in your tests.

### Using Test Helpers

```go
func TestBotBlocking(t *testing.T) {
    // Create a bot fingerprint
    fp := reqdna.TestBotFingerprint()

    if !fp.IsBot() {
        t.Error("should detect as bot")
    }
}

func TestNormalUser(t *testing.T) {
    fp := reqdna.TestFingerprint()
    fp.BotScore = 0.1  // Override any field

    // Test your handler...
}
```

### Using Interfaces (Dependency Injection)

```go
// In your production code
type MyService struct {
    extractor reqdna.Extractor
}

func (s *MyService) HandleRequest(r *http.Request) {
    fp := s.extractor.Extract(r)
    // ...
}

// In your tests
type mockExtractor struct {
    fp reqdna.Fingerprint
}

func (m *mockExtractor) Extract(r *http.Request) reqdna.Fingerprint {
    return m.fp
}

func TestMyService(t *testing.T) {
    mock := &mockExtractor{fp: reqdna.TestBotFingerprint()}
    svc := &MyService{extractor: mock}
    // Test with controlled fingerprint...
}
```

## Performance

```
BenchmarkFromRequest-12    260746    4227 ns/op    1016 B/op    26 allocs/op
```

~4μs per request on modern hardware.

## Use Cases

- **Fraud detection** — identify suspicious requests
- **Rate limiting** — fingerprint-based limits instead of just IP
- **Bot protection** — block automated requests
- **Analytics** — understand your traffic composition
- **Security logging** — enrich logs with request metadata

## License

MIT
