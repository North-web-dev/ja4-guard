package guard

// Category classifies an embedded known fingerprint.
type Category int

const (
	categoryClient  Category = iota // non-browser tooling (curl, wget, Go, ...)
	categoryBrowser                 // web browsers
)

// KnownFingerprint is one entry in the embedded registry. Every value here was
// captured and verified against this library during the build (see Source);
// none are hand-written. JA4 values are specific to a client's TLS library,
// version and platform, so treat these as a starting seed, not an exhaustive
// list. For production, populate your own set from observed traffic or
// https://ja4db.com.
type KnownFingerprint struct {
	Name     string
	JA4      string
	Category Category
	Source   string
}

// knownJA4s returns the JA4 values in the registry for the given category.
func knownJA4s(c Category) []string {
	var out []string
	for _, k := range KnownFingerprints {
		if k.Category == c {
			out = append(out, k.JA4)
		}
	}
	return out
}

// LookupKnown returns the registry entry whose JA4 matches, if any.
func LookupKnown(ja4 string) (KnownFingerprint, bool) {
	for _, k := range KnownFingerprints {
		if k.JA4 == ja4 {
			return k, true
		}
	}
	return KnownFingerprint{}, false
}

// KnownFingerprints is the embedded registry. Every JA4 below was captured
// live against this library on 2026-10-25 by pointing the real client at a
// guard.Listener and reading back its JA4; none are hand-written. JA4 depends
// on the client's TLS stack, version and platform, so these are a seed, not an
// exhaustive list — populate your own from observed traffic or ja4db.com.
var KnownFingerprints = []KnownFingerprint{
	// Browsers (captured via Playwright, Linux x86_64).
	{Name: "Chromium 151", JA4: "t13d1516h2_8daaf6152771_806a8c22fdea", Category: categoryBrowser, Source: "Playwright chromium 151.0.7922.34, 2026-10-25"},
	{Name: "Firefox 153", JA4: "t13d1617h2_86a278354501_3cbfd9057e0d", Category: categoryBrowser, Source: "Playwright firefox 153.0, 2026-10-25"},
	{Name: "WebKit 26.5", JA4: "t13d2913h2_723694b0fccc_5671b5df5029", Category: categoryBrowser, Source: "Playwright webkit 26.5, 2026-10-25"},

	// Non-browser clients.
	{Name: "curl (HTTP/2 ALPN)", JA4: "t13d3113h2_e8f1e7e78f70_ce5650b735ce", Category: categoryClient, Source: "curl 7.81.0 / OpenSSL 3.0.2, 2026-10-25 (cross-checked against tls.peet.ws)"},
	{Name: "curl (HTTP/1.1 ALPN)", JA4: "t13d3113h1_e8f1e7e78f70_ce5650b735ce", Category: categoryClient, Source: "curl 7.81.0 --http1.1 / OpenSSL 3.0.2, 2026-10-25"},
	{Name: "wget", JA4: "t13d751100_479067518aa3_fb8d5ffd48c1", Category: categoryClient, Source: "GNU Wget 1.21.2, 2026-10-25"},
	{Name: "Python urllib", JA4: "t13d181100_85036bcba153_d41ae481755e", Category: categoryClient, Source: "Python-urllib/3.10 / OpenSSL 3.0.2, 2026-10-25"},
	{Name: "OpenSSL s_client", JA4: "t13d311000_e8f1e7e78f70_1f22a2ca17c4", Category: categoryClient, Source: "OpenSSL 3.0.2 s_client, 2026-10-25"},
	{Name: "Go net/http", JA4: "t13d131000_f57a46bbacb6_e7c285222651", Category: categoryClient, Source: "Go 1.23.4 net/http, 2026-10-25"},
}
