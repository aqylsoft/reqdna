package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/aqylsoft/reqdna"
)

func main() {
	mux := http.NewServeMux()

	// Example 1: Using middleware
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
	})

	// Example 2: Direct handler with fingerprint
	mux.Handle("/api/", reqdna.Handler(func(w http.ResponseWriter, r *http.Request, fp reqdna.Fingerprint) {
		// Block bots
		if fp.IsBot() {
			http.Error(w, "Bot detected", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"fingerprint": "%s", "bot_score": %.2f}`, fp.Hash[:16], fp.BotScore)
	}))

	// Wrap with fingerprint middleware
	handler := reqdna.Middleware(mux,
		reqdna.WithHashSalt("my-secret-salt"),
	)

	fmt.Println("Server starting on :8080")
	fmt.Println("Try:")
	fmt.Println("  curl http://localhost:8080/")
	fmt.Println("  curl http://localhost:8080/api/")
	fmt.Println("  curl -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' http://localhost:8080/")

	log.Fatal(http.ListenAndServe(":8080", handler))
}
