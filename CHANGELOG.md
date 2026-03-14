# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-14

### Added

- HTTP request fingerprinting with stable SHA256 hash (`Fingerprint.Hash`)
- IP analysis with privacy-preserving hashing (configurable salt via `WithHashSalt`)
- TLS fingerprinting: version, cipher suite, SNI, and JA3/JA3S via `JA3Info`
- Header order analysis, entropy calculation, and common-browser detection
- Device/browser/OS detection from User-Agent (`DeviceInfo`)
- Bot probability scoring (`BotScore`, `IsBot()`, `IsSuspicious()`)
- `BotScoreBreakdown` — explicit list of every triggered signal with its weight,
  intended for audit logging and compliance explanations
- `net/http` middleware: `Middleware`, `MiddlewareFunc`, `MiddlewareWithJA3`,
  `MiddlewareFuncWithJA3`, `Handler`
- Context helpers: `Get`, `MustGet`
- Options: `WithTLS`, `WithRealIP`, `WithHashSalt`, `WithClientHello`
- JA3 capture utilities: `NewClientHelloStore`, `WrapTLSConfig`, `ComputeJA3`
- Testing helpers: `TestFingerprint`, `TestBotFingerprint`, `TestMobileFingerprint`
- `Extractor` and `ContextExtractor` interfaces for dependency injection

### BotScore stability contract

`BotScore` is the sum of triggered signal weights, capped at 1.0.

The following thresholds are part of the public API:

| Method          | Threshold |
|-----------------|-----------|
| `IsBot()`       | ≥ 0.7     |
| `IsSuspicious()`| ≥ 0.4     |

**Within a minor version (0.x.y):** individual signal weights and the set of
signals will not change in a way that causes a previously-blocking score (≥ 0.7)
to drop below 0.4, or a previously-passing score (< 0.4) to rise above 0.7.
This guarantee lets you safely hardcode thresholds like `> 0.7 → block`.

**Exception:** if a security vulnerability requires an emergency fix to the
scoring logic, weights may change in a patch release. Such changes will be
clearly marked in this changelog with a `SECURITY` label.

**Major version bump** is required for any breaking change to the scoring
algorithm (e.g. renaming signal names in `BotScoreBreakdown`, changing
threshold semantics of `IsBot` / `IsSuspicious`).

### Signal reference (v0.1.0)

These are the signal names returned in `BotScoreBreakdown.Signals`:

| Signal name                    | Weight | Condition                                      |
|-------------------------------|--------|------------------------------------------------|
| `device_type_bot`             | 0.9    | User-Agent parsed as known bot                 |
| `missing_user_agent`          | 0.8    | `User-Agent` header absent                     |
| `missing_accept_language`     | 0.4    | `Accept-Language` header absent                |
| `suspicious_ua`               | 0.4    | UA matches automation pattern (Puppeteer, etc.)|
| `too_few_headers`             | 0.5    | Fewer than 3 headers total                     |
| `missing_accept`              | 0.3    | `Accept` header absent                         |
| `missing_common_browser_headers` | 0.3 | Fewer than 4 standard browser headers         |
| `outdated_tls`                | 0.3    | TLS version < 1.2                              |
| `high_header_entropy`         | 0.2    | Header entropy > 0.7                           |
| `missing_accept_encoding`     | 0.2    | `Accept-Encoding` header absent                |
| `unusual_x_header`            | 0.1    | Non-standard `X-*` header present              |
| `no_tls_production`           | 0.1    | No TLS on a non-local host                     |

Signal names are stable within a minor version and safe to use in rules and
audit log queries.

[0.1.0]: https://github.com/aqylsoft/reqdna/releases/tag/v0.1.0
