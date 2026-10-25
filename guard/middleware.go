package guard

import (
	"log"
	"net/http"
)

// DefaultDenyStatus is the HTTP status returned for denied requests.
const DefaultDenyStatus = http.StatusForbidden

// Guard is an http middleware that applies a Policy to each request's JA4
// fingerprint.
type Guard struct {
	Policy *Policy

	// DenyStatus is the status code sent when a request is denied.
	// Defaults to 403 when zero.
	DenyStatus int

	// DenyBody is written as the response body on denial. Optional.
	DenyBody string

	// Logger, if set, receives one line per decision. When nil, nothing is
	// logged. Use LogOnly on the Policy to observe without blocking.
	Logger *log.Logger

	// OnDecision, if set, is called for every request after the policy runs,
	// before the request is allowed or denied. Useful for metrics.
	OnDecision func(r *http.Request, fp Fingerprint, d Decision)
}

// New returns a Guard with the given policy and default settings.
func New(p *Policy) *Guard {
	return &Guard{Policy: p, DenyStatus: DefaultDenyStatus}
}

// Wrap returns an http.Handler that enforces the policy in front of next.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	status := g.DenyStatus
	if status == 0 {
		status = DefaultDenyStatus
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp, _ := FromRequest(r)
		d := g.Policy.Evaluate(fp.JA4)

		if g.Logger != nil {
			g.Logger.Printf("ja4-guard %s %s ja4=%q ja4h=%q decision=%s allow=%t",
				r.Method, r.URL.Path, fp.JA4, fp.JA4H, d.Reason, d.Allow)
		}
		if g.OnDecision != nil {
			g.OnDecision(r, fp, d)
		}

		if !d.Allow {
			w.Header().Set("X-JA4-Guard", "deny")
			w.WriteHeader(status)
			if g.DenyBody != "" {
				_, _ = w.Write([]byte(g.DenyBody))
			}
			return
		}

		// Pass the fingerprint down so handlers can read it cheaply.
		next.ServeHTTP(w, withFingerprint(r, fp))
	})
}

// Middleware is the func(http.Handler) http.Handler form, for routers that
// expect that signature.
func (g *Guard) Middleware() func(http.Handler) http.Handler {
	return g.Wrap
}
