package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/aqylsoft/reqdna"
)

func main() {
	https := flag.Bool("https", false, "Enable HTTPS with JA3 fingerprinting")
	cert := flag.String("cert", "cert.pem", "TLS certificate file")
	key := flag.String("key", "key.pem", "TLS key file")
	flag.Parse()

	mux := http.NewServeMux()

	// Main handler showing fingerprint details
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fp, ok := reqdna.Get(r.Context())
		if !ok {
			http.Error(w, "Fingerprint not available", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Request Fingerprint\n")
		fmt.Fprintf(w, "==================\n\n")
		fmt.Fprintf(w, "Hash:      %s\n", fp.Hash[:16])
		fmt.Fprintf(w, "Bot Score: %.2f\n", fp.BotScore)
		fmt.Fprintf(w, "Is Bot:    %v\n", fp.IsBot())
		fmt.Fprintf(w, "\nDevice:\n")
		fmt.Fprintf(w, "  Type:    %s\n", fp.Device.Type)
		fmt.Fprintf(w, "  OS:      %s\n", fp.Device.OS)
		fmt.Fprintf(w, "  Browser: %s\n", fp.Device.Browser)
		fmt.Fprintf(w, "\nIP:\n")
		fmt.Fprintf(w, "  Hash:    %s\n", fp.IP.Hash)
		fmt.Fprintf(w, "  Version: IPv%d\n", fp.IP.Version)
		fmt.Fprintf(w, "\nHeaders:\n")
		fmt.Fprintf(w, "  Count:   %d\n", fp.Headers.Count)
		fmt.Fprintf(w, "  Entropy: %.2f\n", fp.Headers.Entropy)
		fmt.Fprintf(w, "\nTLS:\n")
		fmt.Fprintf(w, "  Available: %v\n", fp.TLS.Available)
		if fp.TLS.Available {
			fmt.Fprintf(w, "  Version:   %s\n", fp.TLS.VersionName)
			fmt.Fprintf(w, "  Cipher:    %s\n", fp.TLS.CipherSuiteName)
			fmt.Fprintf(w, "  Hash:      %s\n", fp.TLS.Hash)
			if fp.TLS.JA3 != nil {
				fmt.Fprintf(w, "\nJA3 Fingerprint:\n")
				fmt.Fprintf(w, "  Hash:   %s\n", fp.TLS.JA3.Hash)
				fmt.Fprintf(w, "  String: %s\n", fp.TLS.JA3.String)
			}
		}
	})

	// API endpoint with bot blocking
	mux.Handle("/api/", reqdna.Handler(func(w http.ResponseWriter, r *http.Request, fp reqdna.Fingerprint) {
		if fp.IsBot() {
			http.Error(w, "Bot detected", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		ja3Hash := ""
		if fp.TLS.JA3 != nil {
			ja3Hash = fp.TLS.JA3.Hash
		}
		fmt.Fprintf(w, `{"fingerprint": "%s", "bot_score": %.2f, "ja3": "%s"}`,
			fp.Hash[:16], fp.BotScore, ja3Hash)
	}))

	if *https {
		// HTTPS mode with full JA3 fingerprinting
		store := reqdna.NewClientHelloStore()

		tlsConfig := reqdna.WrapTLSConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}, store)

		handler := reqdna.MiddlewareWithJA3(mux, store,
			reqdna.WithHashSalt("my-secret-salt"),
		)

		server := &http.Server{
			Addr:      ":8443",
			Handler:   handler,
			TLSConfig: tlsConfig,
		}

		fmt.Println("HTTPS server starting on :8443 (with JA3 fingerprinting)")
		fmt.Println("Try:")
		fmt.Println("  curl -k https://localhost:8443/")
		fmt.Println("  curl -k https://localhost:8443/api/")
		fmt.Println("")
		fmt.Println("Generate self-signed cert:")
		fmt.Println("  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'")

		log.Fatal(server.ListenAndServeTLS(*cert, *key))
	} else {
		// HTTP mode (no JA3, TLS not available)
		handler := reqdna.Middleware(mux,
			reqdna.WithHashSalt("my-secret-salt"),
		)

		fmt.Println("HTTP server starting on :8080")
		fmt.Println("Try:")
		fmt.Println("  curl http://localhost:8080/")
		fmt.Println("  curl http://localhost:8080/api/")
		fmt.Println("  curl -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' http://localhost:8080/")
		fmt.Println("")
		fmt.Println("For JA3 fingerprinting, run with -https flag")

		log.Fatal(http.ListenAndServe(":8080", handler))
	}
}
