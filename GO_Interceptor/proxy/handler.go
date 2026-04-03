package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"scrappingdetection/go-interceptor/fingerprint"
	"scrappingdetection/go-interceptor/session"
	tlsi "scrappingdetection/go-interceptor/tls"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const sessionIDKey contextKey = 0

// Handlers builds the middleware chain:
//
//	FingerprintMiddleware → SessionMiddleware → ReverseProxy
//
// cfg.SessionSecret and cfg.RedisURL control whether session tracking is active.
func Handlers(next http.Handler, store *session.Store, secret string) http.Handler {
	return fingerprintMiddleware(sessionMiddleware(next, store, secret))
}

// -----------------------------------------------------------------------
// Fingerprint middleware
// -----------------------------------------------------------------------

// fingerprintMiddleware reads the TLS fingerprint stored by FingerprintListener
// and injects it as X-* headers into the upstream request.
func fingerprintMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fpVal, ok := tlsi.FingerprintStore.Load(r.RemoteAddr); ok {
			fp := fpVal.(*tlsi.ConnectionFingerprint)

			r.Header.Set("X-JA4", fp.JA4)
			r.Header.Set("X-JA4-Raw", fp.JA4Raw)
			r.Header.Set("X-TLS-Fingerprint", fp.TLSFingerprintJSON())
			r.Header.Set("X-HTTP2-Fingerprint", fp.HTTP2FingerprintStr())
			r.Header.Set("X-Client-IP", extractClientIP(r))

			// JA4 database lookup — three prediction levels:
			//   L1 (exact): full JA4 match against ja4db.json
			//   L2 (Part B): cipher-suite hash → browser family (stable across versions)
			//   L3 (Part A): TLS structure heuristic (fallback when hash unknown)
			l1, l2, l3 := fingerprint.LookupJA4All(fp.JA4)
			if l1 != nil {
				r.Header.Set("X-JA4-App-L1", l1.DisplayName())
				r.Header.Set("X-JA4-App", l1.DisplayName())
				if l1.IsThreat() {
					r.Header.Set("X-JA4-Is-Threat", "true")
				}
			}
			if l2 != "" {
				r.Header.Set("X-JA4-App-L2", l2)
				if l1 == nil {
					r.Header.Set("X-JA4-App", l2)
				}
			}
			if l3 != "" {
				r.Header.Set("X-JA4-App-L3", l3)
				if l1 == nil && l2 == "" {
					r.Header.Set("X-JA4-App", l3)
				}
			}

			// HTTP header presence fingerprint — captures which browser-hint headers are
			// present in the request. Used by Next.js to detect UA/header inconsistencies.
			// Note: r.Header is a map so ORDER is lost; only presence is reliable here.
			r.Header.Set("X-Header-Profile", buildHeaderProfile(r))

			// Advanced header analysis: UA coherence, Sec-Fetch validation,
			// presence scoring, HTTP/2 header order comparison.
			analysis := analyzeHeaders(r, fp)
			r.Header.Set("X-Browser-Brand", analysis.BrowserBrand)

			// UA ↔ sec-ch-ua coherence.
			r.Header.Set("X-UA-Coherence", analysis.UACoherence)
			r.Header.Set("X-UA-Score", itoa(analysis.UAScore))

			// Sec-Fetch-* value validity.
			r.Header.Set("X-SecFetch-Valid", analysis.SecFetchValid)
			r.Header.Set("X-SecFetch-Score", itoa(analysis.SecFetchScore))

			// Required header presence.
			if analysis.PresenceNotes != "" {
				r.Header.Set("X-Header-Presence-Notes", analysis.PresenceNotes)
			}
			r.Header.Set("X-Presence-Score", itoa(analysis.PresenceScore))

			// HTTP/2 header order vs canonical profile.
			r.Header.Set("X-Header-Order-Profile", analysis.OrderProfile)
			if analysis.OrderDistance >= 0 {
				r.Header.Set("X-Header-Order-Distance", fmt.Sprintf("%.2f", analysis.OrderDistance))
			}
			r.Header.Set("X-Order-Score", itoa(analysis.OrderScore))

			// Total score (sum of all sub-scores).
			r.Header.Set("X-Header-Anomaly-Score", itoa(analysis.TotalScore))

			// Attach fp and analysis to context so sessionMiddleware can access them.
			ctx := context.WithValue(r.Context(), fingerprintKey{}, fp)
			ctx = context.WithValue(ctx, headerAnalysisKey{}, analysis)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

type fingerprintKey struct{}
type headerAnalysisKey struct{}

func fingerprintFromCtx(r *http.Request) *tlsi.ConnectionFingerprint {
	fp, _ := r.Context().Value(fingerprintKey{}).(*tlsi.ConnectionFingerprint)
	return fp
}

// -----------------------------------------------------------------------
// Session middleware
// -----------------------------------------------------------------------

// sessionMiddleware manages the _fpsid session cookie.
//
//   - If the request carries a valid signed cookie → verify, Touch (request count + TTL
//     refresh), and detect TLS inconsistencies.
//   - If no valid cookie → generate UUID, store full fingerprint in Redis, set cookie.
//
// store and/or secret may be nil/empty; in that case session tracking is skipped
// and only the X-* headers from fingerprintMiddleware are forwarded.
func sessionMiddleware(next http.Handler, store *session.Store, secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if store == nil || secret == "" {
			next.ServeHTTP(w, r)
			return
		}

		fp := fingerprintFromCtx(r)
		ctx := r.Context()

		sid, valid := session.ReadID(r, secret)

		if valid {
			// --- Returning client ---
			count, err := store.Touch(ctx, sid)
			if err != nil {
				slog.Warn("session touch failed", "sid", sid, "err", err)
			}

			// TLS consistency check: compare only the cipher-suite hash (Part B of JA4).
			// Browsers legitimately vary ALPN and extension lists across connections
			// (e.g. Firefox sends h2 on the main request, h1 on some sub-resources),
			// so comparing the full JA4 produces false positives.
			// Part B (middle segment) identifies the TLS stack without that noise.
			if fp != nil && fp.JA4 != "" {
				sd, err := store.GetSession(ctx, sid)
				if err == nil && sd != nil && sd.JA4 != "" && ja4CipherHash(sd.JA4) != ja4CipherHash(fp.JA4) {
					slog.Warn("TLS fingerprint mismatch",
						"sid", sid,
						"stored_ja4", sd.JA4,
						"current_ja4", fp.JA4,
					)
					store.FlagTLSChange(ctx, sid, fp.JA4)
				}
			}

			// Header anomaly score is NOT re-applied on returning clients.
			// It is set once on first request (new client path below).
			// Re-applying it on every request would inflate the Redis score via
			// static asset calls (JS/CSS chunks), causing false-positive blocks.

			// Inject Redis score so Next.js middleware can gate pages without a Redis call.
			if sd, err := store.GetSession(ctx, sid); err == nil && sd != nil {
				r.Header.Set("X-Bot-Score", itoa(sd.Score))
			}

			r.Header.Set("X-Session-ID", sid)
			r.Header.Set("X-Session-Requests", itoa(count))

			} else {
			// --- New client ---
			sid, err := session.GenerateID()
			if err != nil {
				slog.Error("UUID generation failed", "err", err)
				next.ServeHTTP(w, r)
				return
			}

			if fp != nil {
				fp.ClientIP = extractClientIP(r)
				if storeErr := store.StoreFingerprint(ctx, sid, fp); storeErr != nil {
					slog.Warn("fingerprint store failed", "sid", sid, "err", storeErr)
				} else {
					// Check mass usage of this JA4.
					if fp.JA4 != "" {
						if count, err := store.JA4SessionCount(ctx, fp.JA4); err == nil && count > 50 {
							slog.Warn("high JA4 reuse detected",
								"ja4", fp.JA4,
								"session_count", count,
							)
							store.IncrScore(ctx, sid, 5)
						}
					}
					// Apply header anomaly score for new clients.
					if a, ok := r.Context().Value(headerAnalysisKey{}).(HeaderAnalysis); ok && a.TotalScore > 0 {
						store.IncrScore(ctx, sid, a.TotalScore)
					}
				}
			}

			// Set the signed cookie on the response.
			http.SetCookie(w, session.NewCookie(sid, secret, true))
			r.Header.Set("X-Session-ID", sid)
			r.Header.Set("X-Session-Requests", "1")

			slog.Info("new session created",
				"sid", sid,
				"ja4", func() string {
					if fp != nil {
						return fp.JA4
					}
					return ""
				}(),
				"ip", extractClientIP(r),
			)
		}

		// Propagate session ID to upstream via header.
		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// buildHeaderProfile returns a comma-separated list of browser-hint header names
// that are present in the request. Used for UA/header consistency checks in Next.js.
// Only presence is reliable — r.Header is a map so insertion order is not preserved.
func buildHeaderProfile(r *http.Request) string {
	type check struct{ canonical, key string }
	checks := []check{
		{"Sec-Ch-Ua", "sec-ch-ua"},
		{"Sec-Ch-Ua-Mobile", "sec-ch-ua-mobile"},
		{"Sec-Ch-Ua-Platform", "sec-ch-ua-platform"},
		{"Sec-Fetch-Site", "sec-fetch-site"},
		{"Sec-Fetch-Mode", "sec-fetch-mode"},
		{"Sec-Fetch-Dest", "sec-fetch-dest"},
		{"Upgrade-Insecure-Requests", "upgrade-insecure-requests"},
		{"Priority", "priority"},
	}
	present := make([]string, 0, len(checks))
	for _, c := range checks {
		if r.Header.Get(c.canonical) != "" {
			present = append(present, c.key)
		}
	}
	// Also capture raw Client Hint values for coherence checks in Next.js.
	if v := r.Header.Get("Sec-Ch-Ua"); v != "" {
		r.Header.Set("X-Sec-Ch-Ua-Raw", v)
	}
	if v := r.Header.Get("Sec-Ch-Ua-Platform"); v != "" {
		r.Header.Set("X-Sec-Ch-Ua-Platform", v)
	}
	if v := r.Header.Get("Sec-Ch-Ua-Mobile"); v != "" {
		r.Header.Set("X-Sec-Ch-Ua-Mobile", v)
	}
	return strings.Join(present, ",")
}

// ja4CipherHash extracts Part B (cipher-suite hash) from a JA4 string.
// JA4 format: "{prefix}_{partB}_{partC}" — Part B is the middle segment.
// Returns the full JA4 string unchanged if it doesn't match the expected format,
// so the comparison still works (just becomes a full-string compare).
func ja4CipherHash(ja4 string) string {
	parts := strings.SplitN(ja4, "_", 3)
	if len(parts) == 3 {
		return parts[1]
	}
	return ja4
}

// extractClientIP returns the real client IP address.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
