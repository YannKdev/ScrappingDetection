package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/net/http2"

	"scrappingdetection/go-interceptor/config"
	"scrappingdetection/go-interceptor/fingerprint"
	"scrappingdetection/go-interceptor/session"
	tlsi "scrappingdetection/go-interceptor/tls"
)

// BuildServer creates the complete http.Server with:
//   - A FingerprintListener that peeks at TLS ClientHellos
//   - FingerprintMiddleware + SessionMiddleware that inject X-JA4, X-Session-ID headers
//   - A reverse proxy forwarding to UPSTREAM_URL
//   - Full HTTP/2 support with HEADERS-frame order capture
//
// Returns the configured http.Server and the net.Listener it should Serve on.
func BuildServer(cfg *config.Config, store *session.Store) (*http.Server, net.Listener, error) {
	// Parse and validate the upstream URL.
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, nil, err
	}

	// Build the reverse proxy director.
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Capture the original public-facing host BEFORE overwriting req.Host.
			// Next.js Server Actions compare x-forwarded-host against the Origin header
			// for CSRF protection — without this the check fails (localhost:3000 ≠ localhost:8443).
			if req.Host != "" {
				req.Header.Set("X-Forwarded-Host", req.Host)
			}
			// Declare the scheme so Next.js can reconstruct the full origin URL.
			req.Header.Set("X-Forwarded-Proto", "https")

			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host

			// Append our proxy to the X-Forwarded-For chain.
			if prior, ok := req.Header["X-Forwarded-For"]; ok {
				req.Header.Set("X-Forwarded-For", prior[0]+", "+req.RemoteAddr)
			} else {
				req.Header.Set("X-Forwarded-For", req.RemoteAddr)
			}
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("upstream error", "err", err, "path", r.URL.Path)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Load or generate the TLS certificate.
	cert, err := config.LoadTLSCertificate(cfg)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"}, // advertise HTTP/2 + HTTP/1.1
		MinVersion:   tls.VersionTLS12,
	}

	// Create the raw TCP listener.
	rawListener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, nil, err
	}

	// Wrap in our fingerprinting listener (peeks ClientHello, computes JA4).
	fpListener := tlsi.NewFingerprintListener(rawListener, tlsConfig)

	// Build the middleware chain: fingerprint → session → reverse proxy.
	handler := Handlers(rp, store, cfg.SessionSecret)

	// h2srv handles HTTP/2 connections via our custom TLSNextProto hook.
	h2srv := &http2.Server{
		MaxHandlers:          0, // unlimited
		MaxConcurrentStreams: 250,
		IdleTimeout:          120 * time.Second,
	}

	srv := &http.Server{
		Handler: handler,

		// TLSNextProto["h2"] is invoked by the HTTP server when ALPN negotiates "h2".
		// We use this hook instead of http2.ConfigureServer so that we can wrap the
		// tls.Conn in an h2SniffConn that side-copies decrypted bytes for frame parsing.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
			"h2": func(hs *http.Server, c *tls.Conn, h http.Handler) {
				remoteAddr := c.RemoteAddr().String()

				// Wrap the TLS conn so we can side-copy decrypted application bytes.
				sc := &tlsi.H2SniffConn{Conn: c}

				// Goroutine: wait until the buffer has enough bytes, then parse.
				go func() {
					captureH2Fingerprint(sc, remoteAddr)
				}()

				h2srv.ServeConn(sc, &http2.ServeConnOpts{
					Handler:    h,
					BaseConfig: hs,
				})
			},
		},

		// ConnContext is called for each new connection.
		// We register a cleanup goroutine to delete the fingerprint when the connection closes.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			go func() {
				<-ctx.Done()
				tlsi.FingerprintStore.Delete(c.RemoteAddr().String())
			}()
			return ctx
		},

		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return srv, fpListener, nil
}

// captureH2Fingerprint waits for the h2SniffConn buffer to fill, then parses
// HTTP/2 SETTINGS and HEADERS frames to populate the stored ConnectionFingerprint.
func captureH2Fingerprint(sc *tlsi.H2SniffConn, remoteAddr string) {
	// Wait until we have at least 200 bytes or until 80 ms has elapsed.
	deadline := time.Now().Add(80 * time.Millisecond)
	for time.Now().Before(deadline) {
		if sc.Len() >= 200 || sc.Capped() {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	val, ok := tlsi.FingerprintStore.Load(remoteAddr)
	if !ok {
		return
	}
	fp := val.(*tlsi.ConnectionFingerprint)

	data := sc.Snapshot()
	if h2fp, err := fingerprint.ParseHTTP2Settings(data); err == nil {
		fp.HTTP2 = h2fp
		fp.HeaderOrder = h2fp.HeaderOrder
	}

	// Signal that HeaderOrder is available (always, even if empty).
	fp.MarkHeaderOrderReady()
}
