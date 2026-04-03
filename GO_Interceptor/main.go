package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"scrappingdetection/go-interceptor/config"
	"scrappingdetection/go-interceptor/proxy"
	"scrappingdetection/go-interceptor/session"
)

func main() {
	// Structured JSON logging to stdout.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	// Load configuration from environment variables.
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "err", err)
		os.Exit(1)
	}

	// Ensure SESSION_SECRET is set; generate a random one if not (dev mode only).
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = session.FallbackSecret()
		slog.Warn("SESSION_SECRET not set — using random in-process secret (sessions won't survive restarts)")
	}

	slog.Info("starting TLS fingerprint proxy",
		"listen", cfg.ListenAddr,
		"upstream", cfg.UpstreamURL,
		"redis", cfg.RedisURL != "",
	)

	// Connect to Redis if configured (sessions disabled without it).
	var store *session.Store
	if cfg.RedisURL != "" {
		store, err = session.NewStore(cfg.RedisURL)
		if err != nil {
			slog.Error("redis connection failed", "err", err)
			os.Exit(1)
		}
		defer store.Close()
		slog.Info("redis connected", "url", cfg.RedisURL)
	} else {
		slog.Warn("REDIS_URL not set — session tracking disabled (fingerprints logged only)")
	}

	// Build server and fingerprinting listener.
	srv, listener, err := proxy.BuildServer(cfg, store)
	if err != nil {
		slog.Error("failed to build server", "err", err)
		os.Exit(1)
	}

	// Start serving in the background.
	go func() {
		slog.Info("proxy listening", "addr", listener.Addr().String())
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("serve error", "err", err)
			os.Exit(1)
		}
	}()

	// Wait for SIGINT or SIGTERM for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down proxy...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	} else {
		slog.Info("proxy stopped cleanly")
	}
}
