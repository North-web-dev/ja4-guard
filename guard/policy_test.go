package guard

import "testing"

func TestAllowList(t *testing.T) {
	p := NewAllowList("t13d1516h2_8daaf6152771_806a8c22fdea")
	if d := p.Evaluate("t13d1516h2_8daaf6152771_806a8c22fdea"); !d.Allow || d.Reason != "allow-list" {
		t.Errorf("listed JA4: got %+v, want allow/allow-list", d)
	}
	if d := p.Evaluate("t13d3113h2_e8f1e7e78f70_ce5650b735ce"); d.Allow || d.Reason != "default-deny" {
		t.Errorf("unlisted JA4: got %+v, want deny/default-deny", d)
	}
}

func TestDenyList(t *testing.T) {
	p := NewDenyList("t13d3113h2_e8f1e7e78f70_ce5650b735ce")
	if d := p.Evaluate("t13d3113h2_e8f1e7e78f70_ce5650b735ce"); d.Allow || d.Reason != "deny-list" {
		t.Errorf("listed JA4: got %+v, want deny/deny-list", d)
	}
	if d := p.Evaluate("t13d1516h2_8daaf6152771_806a8c22fdea"); !d.Allow || d.Reason != "default-allow" {
		t.Errorf("unlisted JA4: got %+v, want allow/default-allow", d)
	}
}

func TestDenyBeatsAllow(t *testing.T) {
	ja4 := "t13d3113h2_e8f1e7e78f70_ce5650b735ce"
	p := NewAllowList(ja4).Deny(ja4)
	if d := p.Evaluate(ja4); d.Allow {
		t.Errorf("deny should beat allow, got %+v", d)
	}
}

func TestLogOnly(t *testing.T) {
	p := NewAllowList("x")
	p.LogOnly = true
	d := p.Evaluate("not-listed")
	if !d.Allow {
		t.Errorf("log-only must never block, got %+v", d)
	}
	if d.Reason != "log-only:default-deny" {
		t.Errorf("reason = %q, want log-only:default-deny", d.Reason)
	}
}

func TestFailOpenClosed(t *testing.T) {
	open := NewAllowList("x")
	open.FailOpen = true
	if d := open.Evaluate(""); !d.Allow || d.Reason != "no-fingerprint:fail-open" {
		t.Errorf("fail-open: got %+v", d)
	}
	closed := NewAllowList("x")
	closed.FailOpen = false
	if d := closed.Evaluate(""); d.Allow || d.Reason != "no-fingerprint:fail-closed" {
		t.Errorf("fail-closed: got %+v", d)
	}
}

func TestZeroPolicyAllowsAll(t *testing.T) {
	var p Policy
	if d := p.Evaluate("anything"); !d.Allow {
		t.Errorf("zero policy should allow, got %+v", d)
	}
}

func TestKnownPolicies(t *testing.T) {
	// The embedded registry must be populated with verified values.
	if len(KnownFingerprints) == 0 {
		t.Fatal("KnownFingerprints registry is empty")
	}
	bp := KnownBrowserPolicy()
	// Chromium is in the embedded browser set.
	chrome := "t13d1516h2_8daaf6152771_806a8c22fdea"
	if d := bp.Evaluate(chrome); !d.Allow {
		t.Errorf("known-browser policy should allow Chromium, got %+v", d)
	}
	// curl is a client, not a browser: denied by a browser allow-list.
	curl := "t13d3113h2_e8f1e7e78f70_ce5650b735ce"
	if d := bp.Evaluate(curl); d.Allow {
		t.Errorf("known-browser policy should deny curl, got %+v", d)
	}
	// Known-client policy allows curl.
	cp := KnownClientPolicy()
	if d := cp.Evaluate(curl); !d.Allow {
		t.Errorf("known-client policy should allow curl, got %+v", d)
	}
	if k, ok := LookupKnown(chrome); !ok || k.Category != categoryBrowser {
		t.Errorf("LookupKnown(chrome) = %+v, %v", k, ok)
	}
}
