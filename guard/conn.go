package guard

import (
	"bytes"
	"crypto/tls"
	"net"
	"sync"
)

// maxHeadBytes bounds how many bytes of the decrypted stream are buffered
// while looking for the end of the first HTTP request head. If the terminator
// is not found within this budget (e.g. HTTP/2 or a non-HTTP protocol), head
// capture is abandoned and JA4H is left empty.
const maxHeadBytes = 64 * 1024

var headTerminator = []byte("\r\n\r\n")

// Conn is a TLS connection that carries the client's JA4 fingerprint and
// captures the first HTTP/1.x request head (for JA4H). It satisfies net.Conn.
type Conn struct {
	net.Conn // the underlying *tls.Conn

	ja4        string
	ja4Raw     string
	serverName string
	ja4err     error

	mu        sync.Mutex
	capturing bool
	buf       []byte
	head      []byte
	headSet   bool
}

// JA4 returns the client's JA4 fingerprint, or "" if it could not be computed.
func (c *Conn) JA4() string { return c.ja4 }

// JA4Raw returns the raw (unhashed) JA4_r form.
func (c *Conn) JA4Raw() string { return c.ja4Raw }

// ServerName returns the SNI host sent by the client, if any.
func (c *Conn) ServerName() string { return c.serverName }

// JA4Err returns any error encountered while parsing the ClientHello.
func (c *Conn) JA4Err() error { return c.ja4err }

// RequestHead returns the captured raw bytes of the first HTTP/1.x request
// head (up to and including the terminating CRLFCRLF), or nil if none was
// captured (for example HTTP/2 or a non-HTTP client).
func (c *Conn) RequestHead() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}

// NegotiatedProtocol returns the ALPN protocol agreed during the TLS
// handshake (e.g. "h2", "http/1.1"), or "" if none.
func (c *Conn) NegotiatedProtocol() string {
	if tc, ok := c.Conn.(*tls.Conn); ok {
		return tc.ConnectionState().NegotiatedProtocol
	}
	return ""
}

// Read tees the decrypted stream to capture the first HTTP request head.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.capture(p[:n])
	}
	return n, err
}

func (c *Conn) capture(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.capturing {
		return
	}
	// HTTP/2 multiplexes requests with HPACK; its wire bytes are not an
	// HTTP/1.x head, so there is nothing useful to capture for JA4H.
	if c.NegotiatedProtocol() == "h2" {
		c.capturing = false
		return
	}
	c.buf = append(c.buf, b...)
	if idx := bytes.Index(c.buf, headTerminator); idx >= 0 {
		end := idx + len(headTerminator)
		c.head = c.buf[:end]
		c.headSet = true
		c.capturing = false
		c.buf = nil
		return
	}
	if len(c.buf) >= maxHeadBytes {
		// Give up: not an HTTP/1.x head within the budget.
		c.capturing = false
		c.buf = nil
	}
}
