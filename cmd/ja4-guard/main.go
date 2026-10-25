// Command ja4-guard is a small TLS reverse proxy that fingerprints inbound
// clients with JA4 and applies an allow/deny policy before forwarding to an
// upstream.
//
// Example:
//
//	ja4-guard -listen :8443 -upstream http://127.0.0.1:8080 \
//	    -cert server.crt -key server.key \
//	    -deny t13d3113h2_e8f1e7e78f70_ce5650b735ce
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/North-web-dev/ja4-guard/guard"
)

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func main() {
	var (
		listen   = flag.String("listen", ":8443", "address to listen on (TLS)")
		upstream = flag.String("upstream", "", "upstream base URL to proxy to, e.g. http://127.0.0.1:8080")
		certFile = flag.String("cert", "", "path to TLS certificate (PEM)")
		keyFile  = flag.String("key", "", "path to TLS private key (PEM)")
		mode     = flag.String("mode", "deny-list", "policy mode: allow-list | deny-list | known-clients | known-browsers")
		logOnly  = flag.Bool("log-only", false, "never block; only log decisions")
		failOpen = flag.Bool("fail-open", true, "allow requests with no usable fingerprint")
		status   = flag.Int("deny-status", guard.DefaultDenyStatus, "HTTP status for denied requests")
		addHdr   = flag.Bool("set-header", true, "add X-JA4 / X-JA4H headers to proxied requests")
	)
	var allow, deny listFlag
	flag.Var(&allow, "allow", "JA4 value to allow (repeatable or comma-separated)")
	flag.Var(&deny, "deny", "JA4 value to deny (repeatable or comma-separated)")
	flag.Parse()

	if *upstream == "" || *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "ja4-guard: -upstream, -cert and -key are required")
		flag.Usage()
		os.Exit(2)
	}

	target, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("ja4-guard: invalid -upstream: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("ja4-guard: loading cert/key: %v", err)
	}

	policy, err := buildPolicy(*mode, allow, deny)
	if err != nil {
		log.Fatalf("ja4-guard: %v", err)
	}
	policy.LogOnly = *logOnly
	policy.FailOpen = *failOpen

	proxy := httputil.NewSingleHostReverseProxy(target)
	if *addHdr {
		base := proxy.Director
		proxy.Director = func(r *http.Request) {
			base(r)
			if fp, ok := guard.FromRequest(r); ok {
				r.Header.Set("X-JA4", fp.JA4)
				if fp.JA4H != "" {
					r.Header.Set("X-JA4H", fp.JA4H)
				}
			}
		}
	}

	g := &guard.Guard{
		Policy:     policy,
		DenyStatus: *status,
		DenyBody:   "forbidden\n",
		Logger:     log.New(os.Stdout, "", log.LstdFlags),
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("ja4-guard: listen: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	gl := guard.NewListener(ln, tlsCfg)

	srv := &http.Server{
		Handler:     g.Wrap(proxy),
		ConnContext: guard.ConnContext,
	}

	log.Printf("ja4-guard listening on %s -> %s (mode=%s, log-only=%t)", *listen, target, *mode, *logOnly)
	if err := srv.Serve(gl); err != nil {
		log.Fatalf("ja4-guard: serve: %v", err)
	}
}

func buildPolicy(mode string, allow, deny listFlag) (*guard.Policy, error) {
	switch mode {
	case "allow-list":
		p := guard.NewAllowList(allow...)
		p.Deny(deny...)
		return p, nil
	case "deny-list":
		p := guard.NewDenyList(deny...)
		p.Allow(allow...)
		return p, nil
	case "known-clients":
		p := guard.KnownClientPolicy()
		p.Allow(allow...)
		p.Deny(deny...)
		return p, nil
	case "known-browsers":
		p := guard.KnownBrowserPolicy()
		p.Allow(allow...)
		p.Deny(deny...)
		return p, nil
	default:
		return nil, fmt.Errorf("unknown -mode %q", mode)
	}
}
