package tlsinterceptor

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"time"

	"scrappingdetection/go-interceptor/fingerprint"
)

// FingerprintListener wraps a net.Listener to intercept TLS ClientHello messages
// before the TLS handshake completes, enabling JA4 fingerprint extraction.
type FingerprintListener struct {
	inner   net.Listener
	tlsConf *tls.Config
}

// NewFingerprintListener creates a FingerprintListener wrapping inner with the given TLS config.
func NewFingerprintListener(inner net.Listener, tlsConf *tls.Config) *FingerprintListener {
	return &FingerprintListener{inner: inner, tlsConf: tlsConf}
}

// Accept accepts a raw TCP connection, peeks at the TLS ClientHello to extract
// the JA4 fingerprint, stores it in FingerprintStore, then returns a tls.Conn
// wrapping a peekConn that replays the peeked bytes so crypto/tls sees the full stream.
func (l *FingerprintListener) Accept() (net.Conn, error) {
	rawConn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}

	remoteAddr := rawConn.RemoteAddr().String()

	// Set a deadline for the peek phase to avoid hanging on slow/misbehaving clients.
	rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	peekedBytes, err := peekTLSRecord(rawConn)

	// Clear the deadline regardless of parse outcome.
	rawConn.SetReadDeadline(time.Time{})

	if err != nil {
		slog.Warn("TLS peek failed", "remote", remoteAddr, "err", err)
		// Still serve the connection: wrap without fingerprint info.
		rawConn.Close()
		// Accept the next one instead of returning broken conn.
		return l.Accept()
	}

	// Parse ClientHello and compute JA4.
	hello, parseErr := ParseClientHello(peekedBytes)
	fp := NewConnectionFingerprint(remoteAddr)

	if parseErr == nil && hello != nil {
		fp.ClientHello = hello
		ja4Result := fingerprint.ComputeJA4(toFingerprintHello(hello))
		fp.JA4 = ja4Result.JA4
		fp.JA4Raw = ja4Result.JA4Raw
	} else {
		slog.Debug("ClientHello parse error", "remote", remoteAddr, "err", parseErr)
	}

	FingerprintStore.Store(remoteAddr, fp)

	// Construct a peekConn so crypto/tls receives the complete unmodified byte stream.
	peeked := newPeekConn(rawConn, peekedBytes)

	// Return the *tls.Conn directly. http.Server.Serve() requires an exact *tls.Conn
	// via type assertion — any wrapper struct would break TLS setup.
	return tls.Server(peeked, l.tlsConf), nil
}

// Addr returns the listener's network address.
func (l *FingerprintListener) Addr() net.Addr {
	return l.inner.Addr()
}

// Close closes the underlying listener.
func (l *FingerprintListener) Close() error {
	return l.inner.Close()
}

// peekTLSRecord reads a complete TLS record from conn without consuming it from the stream.
// Returns the raw bytes of the record (header + payload).
func peekTLSRecord(conn net.Conn) ([]byte, error) {
	// Read the 5-byte TLS record header.
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// The record payload length is encoded in bytes 3-4 (big-endian uint16).
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384+2048 { // Max TLS record size per spec is 16384, allow small overhead
		return nil, io.ErrUnexpectedEOF
	}

	// Read the handshake payload.
	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	return append(header, payload...), nil
}

// toFingerprintHello converts a tlsinterceptor.ClientHelloData to the fingerprint package type.
func toFingerprintHello(h *ClientHelloData) *fingerprint.ClientHelloData {
	if h == nil {
		return nil
	}

	exts := make([]fingerprint.Extension, len(h.Extensions))
	for i, e := range h.Extensions {
		exts[i] = fingerprint.Extension{Type: e.Type, Data: e.Data}
	}

	return &fingerprint.ClientHelloData{
		RawVersion:          h.RawVersion,
		SupportedVersions:   h.SupportedVersions,
		CipherSuites:        h.CipherSuites,
		Extensions:          exts,
		SupportedGroups:     h.SupportedGroups,
		SignatureAlgorithms: h.SignatureAlgorithms,
		ALPNProtocols:       h.ALPNProtocols,
		SNIHostname:         h.SNIHostname,
	}
}
