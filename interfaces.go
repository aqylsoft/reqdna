package reqdna

import (
	"context"
	"net/http"
)

// Extractor extracts fingerprints from HTTP requests.
// Implement this interface to create custom extractors or mocks for testing.
//
// Example mock in user tests:
//
//	type mockExtractor struct {
//	    fp reqdna.Fingerprint
//	}
//
//	func (m *mockExtractor) Extract(r *http.Request) reqdna.Fingerprint {
//	    return m.fp
//	}
//
//	func TestMyHandler(t *testing.T) {
//	    extractor := &mockExtractor{fp: reqdna.Fingerprint{BotScore: 0.9}}
//	    // Use extractor in your handler...
//	}
type Extractor interface {
	Extract(r *http.Request) Fingerprint
}

// ContextExtractor extracts fingerprints from context.
// Use this to mock fingerprint retrieval in middleware-based architectures.
type ContextExtractor interface {
	FromContext(ctx context.Context) (Fingerprint, bool)
}

// DefaultExtractor is the standard implementation of Extractor.
type DefaultExtractor struct {
	opts []Option
}

// NewExtractor creates a new Extractor with the given options.
//
// Example:
//
//	extractor := reqdna.NewExtractor(
//	    reqdna.WithHashSalt("my-salt"),
//	)
//	fp := extractor.Extract(r)
func NewExtractor(opts ...Option) *DefaultExtractor {
	return &DefaultExtractor{opts: opts}
}

// Extract implements Extractor interface.
func (e *DefaultExtractor) Extract(r *http.Request) Fingerprint {
	return FromRequest(r, e.opts...)
}

// DefaultContextExtractor is the standard implementation of ContextExtractor.
type DefaultContextExtractor struct{}

// FromContext implements ContextExtractor interface.
func (e *DefaultContextExtractor) FromContext(ctx context.Context) (Fingerprint, bool) {
	return Get(ctx)
}

// Compile-time interface compliance checks.
var (
	_ Extractor        = (*DefaultExtractor)(nil)
	_ ContextExtractor = (*DefaultContextExtractor)(nil)
)
