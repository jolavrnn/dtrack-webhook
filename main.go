package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"dtrack-webhook/pkg/cache"
	"dtrack-webhook/pkg/config"
	"dtrack-webhook/pkg/logging"
	"dtrack-webhook/pkg/webhook"
)

var log = logrus.New()

func main() {
	// Setup configuration
	cfg := config.LoadConfig()

	// Setup logging
	logging.SetupLogging(log, cfg.LogLevel, cfg.LogFormat)

	// Validate critical configuration
	if cfg.DtrackURL == "" || cfg.DtrackAPIKey == "" {
		log.Fatal("Missing required environment variables: DTRACK_URL and DTRACK_API_KEY")
	}

	// Initialize cache
	cacheManager := cache.NewCacheManager(cfg.TTLSeconds)

	// Start background cleanup
	go cacheManager.Cleanup()

	// Setup webhook handler
	webhookHandler := webhook.NewWebhookHandler(cfg, cacheManager)

	// Create custom router with security headers
	router := http.NewServeMux()
	router.HandleFunc("/webhook", webhookHandler.HandleWebhook)
	router.HandleFunc("/health", webhookHandler.HealthCheck)

	// Create HTTP server with comprehensive timeouts and limits
	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: addSecurityHeaders(router),
		// Timeout configurations
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second, // Longer for large BOM uploads
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// Size limits
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Channel to listen for errors coming from the listener
	serverErrors := make(chan error, 1)

	// Start server in a goroutine
	go func() {
		log.WithFields(logrus.Fields{
			"port":                cfg.Port,
			"ttl":                 cfg.TTLSeconds,
			"verbose":             cfg.Verbose,
			"read_timeout":        "15s",
			"write_timeout":       "30s",
			"idle_timeout":        "60s",
			"read_header_timeout": "5s",
			"max_header_bytes":    "1MB",
		}).Info("Starting SBOM webhook service")

		serverErrors <- server.ListenAndServe()
	}()

	// Blocking main and waiting for shutdown
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	// Wait for either an error or OS signal
	select {
	case err := <-serverErrors:
		log.Fatalf("Error starting server: %v", err)

	case <-osSignals:
		log.Info("Start shutdown...")

		// Give outstanding requests 30 seconds to complete
		const timeout = 30 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Asking listener to shutdown
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown did not complete in %v: %v", timeout, err)
			if err := server.Close(); err != nil {
				log.Fatalf("Could not stop server gracefully: %v", err)
			}
		}
	}

	log.Info("Shutdown complete")
}

// addSecurityHeaders adds security headers to all responses
func addSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Remove server header
		w.Header().Del("Server")

		next.ServeHTTP(w, r)
	})
}
