package guard

import (
	"context"
	"net"
	"net/http"

	"github.com/North-web-dev/ja4-guard/ja4"
)

type connKey struct{}
type fpKey struct{}

// ConnContext is meant to be assigned to http.Server.ConnContext. It stashes
// the *Conn on the base context of each connection so handlers and middleware
// can retrieve the fingerprint:
//
//	srv := &http.Server{Handler: h, ConnContext: guard.ConnContext}
//	srv.Serve(guard.NewListener(ln, tlsCfg))
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if gc, ok := c.(*Conn); ok {
		return context.WithValue(ctx, connKey{}, gc)
	}
	return ctx
}

func connFromContext(ctx context.Context) (*Conn, bool) {
	gc, ok := ctx.Value(connKey{}).(*Conn)
	return gc, ok
}

// Fingerprint is the inbound-client fingerprint for one request.
type Fingerprint struct {
	JA4        string // TLS fingerprint, e.g. "t13d3113h2_e8f1e7e78f70_ce5650b735ce"
	JA4Raw     string // unhashed JA4_r
	JA4H       string // HTTP fingerprint, or "" if unavailable (e.g. HTTP/2)
	JA4HRaw    string // unhashed JA4H_r
	ServerName string // SNI host, if any
	Err        error  // non-nil if the ClientHello could not be parsed
}

// FromRequest extracts the fingerprint for r. The bool is false when the
// request did not arrive through guard.NewListener + guard.ConnContext.
func FromRequest(r *http.Request) (Fingerprint, bool) {
	// A fingerprint previously computed by the middleware takes precedence.
	if fp, ok := r.Context().Value(fpKey{}).(Fingerprint); ok {
		return fp, true
	}
	gc, ok := connFromContext(r.Context())
	if !ok {
		return Fingerprint{}, false
	}
	return fingerprintOf(gc), true
}

func fingerprintOf(gc *Conn) Fingerprint {
	fp := Fingerprint{
		JA4:        gc.JA4(),
		JA4Raw:     gc.JA4Raw(),
		ServerName: gc.ServerName(),
		Err:        gc.JA4Err(),
	}
	if head := gc.RequestHead(); len(head) > 0 {
		if h, err := ja4.JA4HFromRequestHead(head); err == nil {
			fp.JA4H = h.Value
			fp.JA4HRaw = h.Raw
		}
	}
	return fp
}

// withFingerprint returns a request whose context carries fp, so downstream
// handlers can call FromRequest without recomputing.
func withFingerprint(r *http.Request, fp Fingerprint) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), fpKey{}, fp))
}
