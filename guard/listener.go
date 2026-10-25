// Package guard turns inbound TLS client fingerprints (JA4 / JA4H) into a
// policy decision for a net/http server or a reverse proxy.
//
// It installs a TLS-peeking listener that captures the raw ClientHello before
// the handshake, computes the client's JA4, and makes it (plus the JA4H of the
// HTTP request) available to handlers and to a policy engine.
package guard

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/North-web-dev/ja4-guard/ja4"
)

// DefaultPeekTimeout bounds how long the listener waits for the ClientHello
// before giving up on fingerprinting (the connection still proceeds to the
// normal TLS handshake). It mitigates slow-loris stalls during the peek.
const DefaultPeekTimeout = 5 * time.Second

// Listener wraps a net.Listener. Every accepted connection is peeked for its
// TLS ClientHello, fingerprinted, then handed to crypto/tls for the real
// handshake. Accept returns *Conn values.
type Listener struct {
	inner       net.Listener
	cfg         *tls.Config
	peekTimeout time.Duration
}

// NewListener wraps inner so that accepted connections are TLS-terminated with
// cfg and expose their JA4 fingerprint. The returned listener's Accept yields
// *Conn values whose JA4() is populated once the ClientHello is read.
func NewListener(inner net.Listener, cfg *tls.Config) *Listener {
	return &Listener{inner: inner, cfg: cfg, peekTimeout: DefaultPeekTimeout}
}

// SetPeekTimeout overrides the ClientHello peek timeout. Zero disables it.
func (l *Listener) SetPeekTimeout(d time.Duration) { l.peekTimeout = d }

// Accept implements net.Listener.
func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}

	if l.peekTimeout > 0 {
		_ = raw.SetReadDeadline(time.Now().Add(l.peekTimeout))
	}
	consumed, ch, perr := ja4.ReadClientHello(raw)
	if l.peekTimeout > 0 {
		_ = raw.SetReadDeadline(time.Time{})
	}

	// Replay the bytes we consumed so the TLS handshake sees the full stream.
	replay := &prefixConn{Conn: raw, prefix: consumed}
	tlsConn := tls.Server(replay, l.cfg)

	c := &Conn{Conn: tlsConn, capturing: true}
	if perr == nil && ch != nil {
		c.ja4 = ch.JA4()
		c.ja4Raw = ch.JA4Raw()
		c.serverName = ch.ServerName
	} else {
		c.ja4err = perr
	}
	return c, nil
}

// Close implements net.Listener.
func (l *Listener) Close() error { return l.inner.Close() }

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// prefixConn serves a buffered prefix before reading from the underlying conn.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
