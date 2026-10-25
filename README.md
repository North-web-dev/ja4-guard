# ja4-guard

Fingerprint inbound TLS clients with **JA4** (and **JA4H** from the HTTP
request) and apply a policy — allow, deny, or log-only — by fingerprint. Ships
as a Go library for `net/http` and a standalone reverse proxy.

ja4-guard is the **shield** half of a pair. Its sword is
[`North-web-dev/impersonate-http`](https://github.com/North-web-dev/impersonate-http),
which makes a Go client emit a byte-exact browser TLS fingerprint. Read the
[threat model](#threat-model) before deploying: ja4-guard reliably catches
*lazy* bots, not a determined one.

## What it does

A normal `crypto/tls` server never exposes the client's raw ClientHello, so the
fingerprint is lost before your handler runs. ja4-guard installs a listener that
peeks the ClientHello off the wire **before** the TLS handshake, computes the
client's JA4, hands the bytes on to `crypto/tls` unchanged, and makes the
fingerprint available to your handlers and to a policy engine.

- **JA4** — computed from the ClientHello: TLS version, SNI presence, cipher and
  extension counts, first ALPN, plus a sorted-cipher hash and a
  sorted-extension + signature-algorithm hash. Clean-room implementation of the
  [FoxIO JA4 spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).
- **JA4H** — computed from the first HTTP/1.x request head (method, version,
  cookie/referer presence, header count, Accept-Language, hashed header names
  and cookies). HTTP/2 requests have no JA4H here (see
  [limitations](#limitations)).
- **Policy** — allow-list, deny-list, or "known-client/known-browser" mode
  backed by a small embedded set of verified fingerprints. Actions: allow, deny
  (configurable status, default 403), or log-only.

## Install

```
go get github.com/North-web-dev/ja4-guard
```

Requires Go 1.22+.

## Quickstart: middleware

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/North-web-dev/ja4-guard/guard"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fp, _ := guard.FromRequest(r) // fingerprint of the current client
		fmt.Fprintf(w, "hello — your JA4 is %s\n", fp.JA4)
	})

	// Block curl and Go's default HTTP client; allow everything else.
	policy := guard.NewDenyList(
		"t13d3113h2_e8f1e7e78f70_ce5650b735ce", // curl 7.81 / OpenSSL 3.0.2
		"t13d131000_f57a46bbacb6_e7c285222651", // Go net/http
	)
	g := guard.New(policy)

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Handler:     g.Wrap(mux),        // enforce the policy
		ConnContext: guard.ConnContext,  // carry the fingerprint into requests
	}
	// guard.NewListener peeks each ClientHello, then does the TLS handshake.
	log.Fatal(srv.Serve(guard.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})))
}
```

The two pieces that matter: serve on `guard.NewListener(...)` and set
`ConnContext: guard.ConnContext`. Without both, `guard.FromRequest` returns no
fingerprint and the policy's `FailOpen` setting decides what happens.

## Quickstart: reverse proxy

`cmd/ja4-guard` applies a policy in front of an upstream:

```
go build -o ja4-guard ./cmd/ja4-guard

./ja4-guard \
  -listen :8443 \
  -upstream http://127.0.0.1:8080 \
  -cert server.crt -key server.key \
  -mode deny-list \
  -deny t13d3113h2_e8f1e7e78f70_ce5650b735ce
```

Allowed requests are forwarded with `X-JA4` (and `X-JA4H` when available) added
so the upstream can see the fingerprint. Denied requests get a 403.

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:8443` | TLS listen address |
| `-upstream` | — | upstream base URL (required) |
| `-cert` / `-key` | — | TLS cert and key, PEM (required) |
| `-mode` | `deny-list` | `allow-list`, `deny-list`, `known-clients`, `known-browsers` |
| `-allow` / `-deny` | — | JA4 values (repeatable or comma-separated) |
| `-log-only` | `false` | never block; only log decisions |
| `-fail-open` | `true` | allow requests with no usable fingerprint |
| `-deny-status` | `403` | status for denied requests |
| `-set-header` | `true` | add `X-JA4`/`X-JA4H` to proxied requests |

## Policy modes

One `guard.Policy` covers the common cases. Deny entries always beat allow
entries. `LogOnly` forces every decision to allow while still reporting what a
blocking policy would have done.

```go
guard.NewDenyList(ja4...)      // allow all except these
guard.NewAllowList(ja4...)     // deny all except these
guard.KnownClientPolicy()      // allow only recognized CLI/library clients
guard.KnownBrowserPolicy()     // allow only recognized browsers
```

The embedded registry (`guard.KnownFingerprints`) holds a small set of
fingerprints captured live and verified during the build. JA4 depends on the
client's TLS stack, version and platform, so treat it as a seed — populate your
own set from observed traffic or [ja4db.com](https://ja4db.com).

## Threat model

**Be honest about what this does.** JA4 is a fingerprint of the ClientHello. A
client that fully controls its TLS stack can craft a ClientHello that produces
any JA4 it wants — including a real browser's. Our own
[`impersonate-http`](https://github.com/North-web-dev/impersonate-http) does
exactly that. So:

- ja4-guard **catches lazy / honest bots**: `curl`, `wget`, `python-requests` /
  `urllib`, `Go net/http`, `openssl s_client`, headless scrapers that keep their
  default TLS stack, and traffic whose TLS fingerprint doesn't match the
  browser it claims to be in its `User-Agent` (JA4 vs JA4H/UA mismatch).
- ja4-guard does **not** stop a determined adversary who spoofs a browser JA4.
  Against that, JA4 is one weak signal among many — combine it with rate limits,
  behavioral analysis, auth, and proof-of-work challenges.

Use it as a cheap first filter that removes the easy 90%, not as an
authentication mechanism.

## Verification

The JA4 implementation is checked against independent references, not just
against itself:

- **curl, cross-checked against [tls.peet.ws](https://tls.peet.ws).** The raw
  ClientHello from `curl 7.81.0 / OpenSSL 3.0.2` computes to
  `t13d3113h2_e8f1e7e78f70_ce5650b735ce` — the exact JA4 that tls.peet.ws
  reports for the same curl. This raw-bytes case is a unit test
  (`TestJA4FromCapturedBytes`).
- **The FoxIO spec's worked example.** `TestJA4SpecVector` reproduces the
  spec's documented fingerprint `t13d1516h2_8daaf6152771_e5627efa2ab1` from its
  documented input, including the two SHA-256 sub-hashes.
- **Chromium cross-check.** A live Chromium capture produces
  `t13d1516h2_8daaf6152771_...`; its `t13d1516h2` prefix and cipher hash
  `8daaf6152771` are the same values the FoxIO spec documents for Chrome.
- **JA4H against the FoxIO reference `ja4h.py`.** `TestJA4HVectors` reproduces
  values generated by the reference implementation.

Fingerprints captured live during the build (Linux x86_64, 2026-10-25):

| Client | JA4 |
|---|---|
| Chromium 151 | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Firefox 153 | `t13d1617h2_86a278354501_3cbfd9057e0d` |
| WebKit 26.5 | `t13d2913h2_723694b0fccc_5671b5df5029` |
| curl 7.81 (h2 ALPN) | `t13d3113h2_e8f1e7e78f70_ce5650b735ce` |
| curl 7.81 (`--http1.1`) | `t13d3113h1_e8f1e7e78f70_ce5650b735ce` |
| wget 1.21.2 | `t13d751100_479067518aa3_fb8d5ffd48c1` |
| Python-urllib 3.10 | `t13d181100_85036bcba153_d41ae481755e` |
| OpenSSL 3.0.2 s_client | `t13d311000_e8f1e7e78f70_1f22a2ca17c4` |
| Go 1.23.4 net/http | `t13d131000_f57a46bbacb6_e7c285222651` |

## Limitations

- **JA4H is HTTP/1.x only.** It is reconstructed from the raw request head. For
  HTTP/2 the wire bytes are HPACK-encoded framing, not an HTTP/1.x head, so
  `Fingerprint.JA4H` is empty for h2 connections. JA4 (TLS) is unaffected.
- **JA4H reflects the first request on a connection.** Head capture stops after
  the first request head; for keep-alive connections, subsequent requests are
  not re-parsed.
- **JA4 is spoofable.** See [threat model](#threat-model).
- **The embedded fingerprint set is a seed, not a database.** JA4 values vary by
  TLS library, version and OS. Maintain your own allow/deny sets from your
  traffic.
- The peek adds one buffered read per connection and a bounded in-memory buffer
  (64 KiB) while locating the end of the first request head.

## Layout

```
ja4/     JA4 + JA4H computation and ClientHello parsing (no deps)
guard/   TLS-peeking listener, policy engine, net/http middleware
cmd/ja4-guard/   standalone reverse proxy
```

## Support

If this saved you time, a ⭐ on the repo is appreciated. Tips welcome:

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## License

MIT — see [LICENSE](LICENSE). JA4 was created by FoxIO; this is an independent
reimplementation of the public spec.
