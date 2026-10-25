package guard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// selfSignedCert builds an in-memory certificate for tests.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ja4-guard-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startServer runs a guard-protected HTTP/1.1 server and returns its address.
// The handler echoes the computed fingerprint in response headers.
func startServer(t *testing.T, g *Guard) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	gl := NewListener(ln, cfg)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp, ok := FromRequest(r)
		if ok {
			w.Header().Set("X-Seen-JA4", fp.JA4)
			w.Header().Set("X-Seen-JA4H", fp.JA4H)
		}
		io.WriteString(w, "ok")
	})
	srv := &http.Server{Handler: g.Wrap(h), ConnContext: ConnContext}
	go srv.Serve(gl)
	return gl.Addr().String(), func() { srv.Close() }
}

func httpsClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
			ForceAttemptHTTP2: false,
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
}

// TestEndToEnd verifies the full path: TLS peek -> JA4 -> policy -> response,
// using a real Go TLS client against a real listener.
func TestEndToEnd(t *testing.T) {
	// 1. Learn this Go client's own JA4 via an allow-all server.
	addr, stop := startServer(t, New(NewDenyList()))
	client := httpsClient()
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		stop()
		t.Fatalf("request: %v", err)
	}
	clientJA4 := resp.Header.Get("X-Seen-JA4")
	clientJA4H := resp.Header.Get("X-Seen-JA4H")
	resp.Body.Close()
	stop()

	if clientJA4 == "" {
		t.Fatal("no JA4 observed for the Go TLS client")
	}
	if len(clientJA4) < 3 || clientJA4[0] != 't' {
		t.Errorf("unexpected JA4 shape: %q", clientJA4)
	}
	if clientJA4H == "" {
		t.Error("expected a JA4H for the HTTP/1.1 client, got none")
	}
	t.Logf("observed Go client JA4=%s JA4H=%s", clientJA4, clientJA4H)

	// 2. Deny that JA4: request must be rejected with 403.
	addr2, stop2 := startServer(t, New(NewDenyList(clientJA4)))
	defer stop2()
	resp2, err := httpsClient().Get("https://" + addr2 + "/")
	if err != nil {
		t.Fatalf("request2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("denied request: status = %d, want 403", resp2.StatusCode)
	}
	if resp2.Header.Get("X-JA4-Guard") != "deny" {
		t.Errorf("missing X-JA4-Guard: deny header")
	}

	// 3. Allow-list that JA4: request must pass.
	addr3, stop3 := startServer(t, New(NewAllowList(clientJA4)))
	defer stop3()
	resp3, err := httpsClient().Get("https://" + addr3 + "/")
	if err != nil {
		t.Fatalf("request3: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("allowed request: status = %d, want 200", resp3.StatusCode)
	}

	// 4. Log-only deny: logged as deny but still served.
	p := NewDenyList(clientJA4)
	p.LogOnly = true
	addr4, stop4 := startServer(t, New(p))
	defer stop4()
	resp4, err := httpsClient().Get("https://" + addr4 + "/")
	if err != nil {
		t.Fatalf("request4: %v", err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("log-only request: status = %d, want 200", resp4.StatusCode)
	}
}
