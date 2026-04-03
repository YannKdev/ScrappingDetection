// Package session manages client session IDs that tie TLS fingerprints
// (captured at the network layer) to subsequent application-layer signals
// (JS fingerprints, click patterns, etc.) via a signed cookie.
//
// Cookie format: _fpsid=<uuid>.<hmac16>
//   - uuid   : crypto/rand UUID v4
//   - hmac16 : first 16 hex chars of HMAC-SHA256(uuid, SESSION_SECRET)
//
// The cookie is HttpOnly + Secure + SameSite=Lax so JS cannot read it,
// but it is sent on every same-site HTTPS request automatically.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	CookieName = "_fpsid"
	cookieTTL  = 30 * time.Minute
	hmacLen    = 16 // hex chars of the truncated HMAC
)

// GenerateID returns a cryptographically random UUID v4 string.
func GenerateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Set UUID v4 version and variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Sign returns the signed cookie value: "<id>.<hmac16>".
func Sign(id, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id))
	sig := hex.EncodeToString(mac.Sum(nil))[:hmacLen]
	return id + "." + sig
}

// Verify parses and validates a signed cookie value.
// Returns the UUID and true if the signature is valid, ("", false) otherwise.
func Verify(cookieValue, secret string) (string, bool) {
	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	id, sig := parts[0], parts[1]
	if len(sig) != hmacLen {
		return "", false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id))
	expected := hex.EncodeToString(mac.Sum(nil))[:hmacLen]

	// Constant-time comparison to prevent timing attacks.
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}
	return id, true
}

// NewCookie builds the Set-Cookie header for the session ID.
func NewCookie(id, secret string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    Sign(id, secret),
		Path:     "/",
		MaxAge:   int(cookieTTL.Seconds()),
		HttpOnly: true,             // not readable by JS
		Secure:   secure,           // HTTPS only (always true for our TLS proxy)
		SameSite: http.SameSiteLaxMode,
	}
}

// ReadID extracts and verifies the session ID from the request cookie.
// Returns ("", false) if the cookie is absent or the signature is invalid.
func ReadID(r *http.Request, secret string) (string, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", false
	}
	return Verify(c.Value, secret)
}

// FallbackSecret generates a random in-process secret when SESSION_SECRET is not set.
// Only suitable for development — sessions won't survive restarts.
func FallbackSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// cookieExpiry returns the absolute expiry time for display/logging purposes.
func cookieExpiry() time.Time {
	return time.Now().Add(cookieTTL)
}