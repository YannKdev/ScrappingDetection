package tlsinterceptor

import (
	"bytes"
	"io"
	"net"
	"sync"
)

// peekConn wraps a net.Conn and replays a pre-read buffer before reading from the real connection.
// This allows crypto/tls to see the full unmodified byte stream even though we already
// read the ClientHello bytes for fingerprinting.
type peekConn struct {
	net.Conn
	reader io.Reader // io.MultiReader(buffered_peeked_bytes, real_conn)
}

// Read first drains the pre-read buffer, then falls through to the real connection.
func (c *peekConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// newPeekConn constructs a peekConn that will replay peeked before reading from conn.
func newPeekConn(conn net.Conn, peeked []byte) *peekConn {
	return &peekConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peeked), conn),
	}
}

// H2SniffConn wraps a net.Conn and side-copies the first maxSniffBytes of decrypted
// application data for HTTP/2 frame parsing (SETTINGS + HEADERS order).
// After the cap is reached, reads pass through unmodified with zero overhead.
const maxSniffBytes = 4096

// H2SniffConn is exported so that proxy/proxy.go can use it in TLSNextProto handlers.
type H2SniffConn struct {
	net.Conn
	mu     sync.Mutex
	buf    []byte
	capped bool
}

// Read forwards to the underlying conn and copies bytes into the sniff buffer
// until maxSniffBytes is reached.
func (c *H2SniffConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if !c.capped {
			remaining := maxSniffBytes - len(c.buf)
			if remaining >= n {
				c.buf = append(c.buf, b[:n]...)
			} else {
				c.buf = append(c.buf, b[:remaining]...)
				c.capped = true
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

// Snapshot returns a copy of the bytes captured so far.
func (c *H2SniffConn) Snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, len(c.buf))
	copy(out, c.buf)
	return out
}

// Len returns the current number of captured bytes.
func (c *H2SniffConn) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.buf)
}

// Capped reports whether the sniff buffer has reached its maximum size.
func (c *H2SniffConn) Capped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capped
}
