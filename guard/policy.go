package guard

import "strings"

// Action is the default disposition when no explicit list entry matches.
type Action int

const (
	// ActionAllow lets unmatched fingerprints through (deny-list semantics).
	ActionAllow Action = iota
	// ActionDeny blocks unmatched fingerprints (allow-list / known-client
	// semantics).
	ActionDeny
)

// Decision is the outcome of evaluating a fingerprint against a Policy.
type Decision struct {
	Allow  bool   // whether the request should be allowed through
	Reason string // short, log-friendly explanation of the match
	JA4    string // the JA4 that was evaluated
}

// Policy decides whether a given JA4 is allowed. A single struct expresses
// three common modes:
//
//   - Deny-list:     Default=ActionAllow, DenyJA4 populated.
//   - Allow-list:    Default=ActionDeny,  AllowJA4 populated.
//   - Known-client:  Default=ActionDeny,  AllowJA4 = a set of known-good JA4s
//     (see KnownBrowserPolicy / KnownClientPolicy).
//
// Deny entries always win over allow entries. When LogOnly is true the policy
// never blocks: Decision.Allow is always true, but Reason still reflects what
// a blocking policy would have done.
//
// The zero Policy allows everything.
type Policy struct {
	Default  Action
	AllowJA4 map[string]struct{}
	DenyJA4  map[string]struct{}
	LogOnly  bool

	// FailOpen controls behavior when a request has no JA4 (for example it did
	// not come through the peeking listener, or the ClientHello failed to
	// parse). True allows it through; false denies it. Default is true.
	FailOpen bool
}

// NewAllowList returns an allow-list policy: only the listed JA4s are allowed.
func NewAllowList(ja4s ...string) *Policy {
	return &Policy{Default: ActionDeny, AllowJA4: toSet(ja4s), FailOpen: true}
}

// NewDenyList returns a deny-list policy: everything is allowed except the
// listed JA4s.
func NewDenyList(ja4s ...string) *Policy {
	return &Policy{Default: ActionAllow, DenyJA4: toSet(ja4s), FailOpen: true}
}

// KnownClientPolicy returns an allow-list policy seeded with the embedded set
// of verified non-browser client fingerprints (curl, wget, Go, etc.). This is
// the inverse of a bot filter: use it to allow only recognized tooling.
func KnownClientPolicy() *Policy {
	return NewAllowList(knownJA4s(categoryClient)...)
}

// KnownBrowserPolicy returns an allow-list policy seeded with the embedded set
// of verified browser fingerprints. Only recognized browsers are allowed.
func KnownBrowserPolicy() *Policy {
	return NewAllowList(knownJA4s(categoryBrowser)...)
}

// Allow adds JA4 values to the allow-list.
func (p *Policy) Allow(ja4s ...string) *Policy {
	if p.AllowJA4 == nil {
		p.AllowJA4 = map[string]struct{}{}
	}
	for _, j := range ja4s {
		if j = strings.TrimSpace(j); j != "" {
			p.AllowJA4[j] = struct{}{}
		}
	}
	return p
}

// Deny adds JA4 values to the deny-list.
func (p *Policy) Deny(ja4s ...string) *Policy {
	if p.DenyJA4 == nil {
		p.DenyJA4 = map[string]struct{}{}
	}
	for _, j := range ja4s {
		if j = strings.TrimSpace(j); j != "" {
			p.DenyJA4[j] = struct{}{}
		}
	}
	return p
}

// Evaluate decides whether ja4 is allowed. An empty ja4 means the fingerprint
// was unavailable and FailOpen governs the result.
func (p *Policy) Evaluate(ja4 string) Decision {
	if ja4 == "" {
		if p.FailOpen {
			return p.finalize(Decision{Allow: true, Reason: "no-fingerprint:fail-open", JA4: ja4})
		}
		return p.finalize(Decision{Allow: false, Reason: "no-fingerprint:fail-closed", JA4: ja4})
	}

	if _, ok := p.DenyJA4[ja4]; ok {
		return p.finalize(Decision{Allow: false, Reason: "deny-list", JA4: ja4})
	}
	if _, ok := p.AllowJA4[ja4]; ok {
		return p.finalize(Decision{Allow: true, Reason: "allow-list", JA4: ja4})
	}
	if p.Default == ActionDeny {
		return p.finalize(Decision{Allow: false, Reason: "default-deny", JA4: ja4})
	}
	return p.finalize(Decision{Allow: true, Reason: "default-allow", JA4: ja4})
}

// finalize applies LogOnly, which forces Allow=true while keeping the reason.
func (p *Policy) finalize(d Decision) Decision {
	if p.LogOnly && !d.Allow {
		d.Reason = "log-only:" + d.Reason
		d.Allow = true
	}
	return d
}

func toSet(in []string) map[string]struct{} {
	m := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = struct{}{}
		}
	}
	return m
}
