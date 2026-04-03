package tlsinterceptor

import (
	"encoding/json"
	"sync"
	"time"

	"scrappingdetection/go-interceptor/fingerprint"
)

// FingerprintStore is a concurrent map from remote addr string to ConnectionFingerprint.
// Written during Accept(), read by the HTTP middleware, deleted when connection closes.
var FingerprintStore = &sync.Map{}

// ClientHelloData holds all fields extracted from a TLS ClientHello message.
type ClientHelloData struct {
	RawVersion          uint16      // legacy_version field
	SupportedVersions   []uint16    // from extension 0x002b (TLS 1.3 signaling)
	CipherSuites        []uint16    // all cipher suites including GREASE
	CompressionMethods  []uint8
	Extensions          []Extension // all extensions in wire order
	SupportedGroups     []uint16    // from extension 0x000a (elliptic curves)
	SignatureAlgorithms  []uint16    // from extension 0x000d
	ALPNProtocols       []string    // from extension 0x0010
	SNIHostname         string      // from extension 0x0000, empty if IP
}

// Extension represents a single TLS extension with its type and raw data.
type Extension struct {
	Type uint16
	Data []byte
}

// ConnectionFingerprint holds all captured fingerprint data for a single client connection.
type ConnectionFingerprint struct {
	RemoteAddr  string
	ClientIP    string

	// TLS layer
	ClientHello *ClientHelloData

	// JA4
	JA4    string
	JA4Raw string

	// HTTP/2 (nil if HTTP/1.1 or not yet parsed).
	// Uses fingerprint.HTTP2Fingerprint to avoid type duplication.
	HTTP2 *fingerprint.HTTP2Fingerprint

	// HeaderOrder contains HTTP header names in wire order (HTTP/2 only).
	// Populated asynchronously; wait on headerOrderReady before reading.
	HeaderOrder []string

	// headerOrderReady is closed once HeaderOrder (and HTTP2) are populated.
	// Always initialised by NewConnectionFingerprint.
	headerOrderReady chan struct{}

	CapturedAt time.Time
}

// NewConnectionFingerprint creates a ConnectionFingerprint with the ready channel initialised.
func NewConnectionFingerprint(remoteAddr string) *ConnectionFingerprint {
	return &ConnectionFingerprint{
		RemoteAddr:       remoteAddr,
		headerOrderReady: make(chan struct{}),
		CapturedAt:       time.Now(),
	}
}

// HeaderOrderReady returns the channel that is closed when HeaderOrder is available.
// Safe to select on from any goroutine.
func (fp *ConnectionFingerprint) HeaderOrderReady() <-chan struct{} {
	return fp.headerOrderReady
}

// MarkHeaderOrderReady closes headerOrderReady. Must be called exactly once.
func (fp *ConnectionFingerprint) MarkHeaderOrderReady() {
	close(fp.headerOrderReady)
}

// TLSFingerprintJSON returns a JSON string of the key TLS parameters.
func (fp *ConnectionFingerprint) TLSFingerprintJSON() string {
	if fp.ClientHello == nil {
		return "{}"
	}

	// Extract extension type IDs in wire order (without raw data).
	extTypes := make([]uint16, len(fp.ClientHello.Extensions))
	for i, ext := range fp.ClientHello.Extensions {
		extTypes[i] = ext.Type
	}

	data := map[string]interface{}{
		"version":              fp.ClientHello.RawVersion,
		"supported_versions":   fp.ClientHello.SupportedVersions,
		"cipher_suites":        fp.ClientHello.CipherSuites,
		"supported_groups":     fp.ClientHello.SupportedGroups,
		"signature_algorithms": fp.ClientHello.SignatureAlgorithms,
		"alpn":                 fp.ClientHello.ALPNProtocols,
		"sni":                  fp.ClientHello.SNIHostname,
		"extensions":           extTypes,
	}
	b, _ := json.Marshal(data)
	return string(b)
}

// HTTP2FingerprintStr returns the HTTP/2 fingerprint string, or empty string if HTTP/1.1.
func (fp *ConnectionFingerprint) HTTP2FingerprintStr() string {
	if fp.HTTP2 == nil {
		return ""
	}
	return fp.HTTP2.Raw
}

// IsGREASE returns true if v is a GREASE value per RFC 8701.
// GREASE values follow the pattern where both bytes are equal and end in 0xA.
func IsGREASE(v uint16) bool {
	lo := v & 0xff
	hi := v >> 8
	return lo == hi && lo&0x0f == 0x0a
}
