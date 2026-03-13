package reqdna

import (
	"context"
	"crypto/tls"
	"net/http"
)

// contextKey is the type for context keys.
type contextKey struct{ name string }

// FingerprintKey is the context key for storing fingerprints.
var FingerprintKey = &contextKey{"fingerprint"}

// Middleware creates a net/http middleware that extracts fingerprints.
// The fingerprint is stored in the request context and can be retrieved
// using Get(r.Context()).
//
// Example:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/", handler)
//	http.ListenAndServe(":8080", reqdna.Middleware(mux))
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    fp, ok := reqdna.Get(r.Context())
//	    if ok {
//	        fmt.Println(fp.Hash)
//	    }
//	}
func Middleware(next http.Handler, opts ...Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp := FromRequest(r, opts...)
		ctx := context.WithValue(r.Context(), FingerprintKey, fp)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareFunc creates a middleware function for use with routers
// that expect func(http.Handler) http.Handler signature.
//
// Example with chi:
//
//	r := chi.NewRouter()
//	r.Use(reqdna.MiddlewareFunc())
func MiddlewareFunc(opts ...Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return Middleware(next, opts...)
	}
}

// Get retrieves the fingerprint from the context.
// Returns the fingerprint and true if found, zero value and false otherwise.
//
// Example:
//
//	fp, ok := reqdna.Get(r.Context())
//	if !ok {
//	    // Fingerprint not available (middleware not used)
//	}
func Get(ctx context.Context) (Fingerprint, bool) {
	fp, ok := ctx.Value(FingerprintKey).(Fingerprint)
	return fp, ok
}

// MustGet retrieves the fingerprint from the context.
// Panics if the fingerprint is not found.
// Use this only when you're certain the middleware is installed.
func MustGet(ctx context.Context) Fingerprint {
	fp, ok := Get(ctx)
	if !ok {
		panic("reqdna: fingerprint not found in context (middleware not installed?)")
	}
	return fp
}

// HandlerFunc is a convenience type for handlers that need the fingerprint.
type HandlerFunc func(w http.ResponseWriter, r *http.Request, fp Fingerprint)

// Handler wraps a HandlerFunc to automatically extract the fingerprint.
//
// Example:
//
//	http.Handle("/", reqdna.Handler(func(w http.ResponseWriter, r *http.Request, fp reqdna.Fingerprint) {
//	    if fp.IsBot() {
//	        http.Error(w, "Bot detected", http.StatusForbidden)
//	        return
//	    }
//	    // ...
//	}))
func Handler(fn HandlerFunc, opts ...Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp := FromRequest(r, opts...)
		fn(w, r, fp)
	})
}

// MiddlewareWithJA3 creates middleware with full JA3 fingerprinting support.
// It automatically retrieves ClientHello from the store and includes it in fingerprint.
//
// Example:
//
//	store := reqdna.NewClientHelloStore()
//	tlsConfig := reqdna.WrapTLSConfig(&tls.Config{...}, store)
//
//	handler := reqdna.MiddlewareWithJA3(mux, store)
//
//	server := &http.Server{
//	    TLSConfig: tlsConfig,
//	    Handler:   handler,
//	}
func MiddlewareWithJA3(next http.Handler, store *ClientHelloStore, opts ...Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get ClientHello from store
		var hello *tls.ClientHelloInfo
		if store != nil {
			hello = store.Get(r.RemoteAddr)
		}

		// Build options with ClientHello
		allOpts := make([]Option, 0, len(opts)+1)
		if hello != nil {
			allOpts = append(allOpts, WithClientHello(hello))
		}
		allOpts = append(allOpts, opts...)

		// Extract fingerprint
		fp := FromRequest(r, allOpts...)
		ctx := context.WithValue(r.Context(), FingerprintKey, fp)

		// Clean up store entry after request
		if store != nil {
			defer store.Delete(r.RemoteAddr)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareFuncWithJA3 creates a middleware function with JA3 support
// for use with routers that expect func(http.Handler) http.Handler signature.
//
// Example with chi:
//
//	store := reqdna.NewClientHelloStore()
//	r := chi.NewRouter()
//	r.Use(reqdna.MiddlewareFuncWithJA3(store))
func MiddlewareFuncWithJA3(store *ClientHelloStore, opts ...Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return MiddlewareWithJA3(next, store, opts...)
	}
}
