package ja4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// specClientHello builds the ClientHello from the worked example in the FoxIO
// JA4 spec (technical_details/JA4.md), which documents the exact expected
// fingerprint and its components.
func specClientHello() *ClientHello {
	ciphers := []uint16{
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
		0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}
	exts := []uint16{
		0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
		0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
	}
	sigalgs := []uint16{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
	}
	return &ClientHello{
		LegacyVersion:       0x0303,
		CipherSuites:        ciphers,
		Extensions:          exts,
		SupportedVersions:   []uint16{0x0304},
		SignatureAlgorithms: sigalgs,
		ALPN:                []string{"h2"},
		HasSNI:              true,
		ServerName:          "example.com",
	}
}

func TestJA4SpecVector(t *testing.T) {
	ch := specClientHello()

	const wantJA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got := ch.JA4(); got != wantJA4 {
		t.Errorf("JA4() = %q, want %q", got, wantJA4)
	}

	const wantRaw = "t13d1516h2_" +
		"002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_" +
		"0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_" +
		"0403,0804,0401,0503,0805,0501,0806,0601"
	if got := ch.JA4Raw(); got != wantRaw {
		t.Errorf("JA4Raw() =\n  %q\nwant\n  %q", got, wantRaw)
	}

	if got := ch.JA4A(TransportTCP); got != "t13d1516h2" {
		t.Errorf("JA4A() = %q, want t13d1516h2", got)
	}
}

// capturedHellos holds raw TLS ClientHello bytes captured live from real
// clients during the build, each with a JA4 verified independently.
var capturedHellos = []struct {
	name    string
	hex     string
	wantJA4 string
}{
	{
		// curl 7.81.0 (OpenSSL 3.0.2), default HTTP/2 ALPN offer.
		// Cross-checked: tls.peet.ws reports the same JA4 for this curl.
		name:    "curl-7.81.0",
		hex:     curlHelloHex,
		wantJA4: "t13d3113h2_e8f1e7e78f70_ce5650b735ce",
	},
	{
		// Go 1.23.4 net/http default client.
		name:    "go-net-http-1.23.4",
		hex:     goHelloHex,
		wantJA4: "t13d131000_f57a46bbacb6_e7c285222651",
	},
}

func TestJA4FromCapturedBytes(t *testing.T) {
	for _, tc := range capturedHellos {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			consumed, ch, err := ReadClientHello(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("ReadClientHello: %v", err)
			}
			if !bytes.HasPrefix(raw, consumed) {
				t.Errorf("consumed bytes are not a prefix of input")
			}
			if got := ch.JA4(); got != tc.wantJA4 {
				t.Errorf("JA4() = %q, want %q", got, tc.wantJA4)
			}
		})
	}
}

func TestReadClientHelloRejectsNonHandshake(t *testing.T) {
	// A plain HTTP request on a TLS port is not a ClientHello.
	_, _, err := ReadClientHello(bytes.NewReader([]byte("GET / HTTP/1.1\r\n\r\n")))
	if err == nil {
		t.Fatal("expected error for non-TLS input")
	}
}

func TestIsGREASE(t *testing.T) {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x8a8a, 0xaaaa, 0xbaba, 0xfafa}
	for _, v := range grease {
		if !isGREASE(v) {
			t.Errorf("isGREASE(0x%04x) = false, want true", v)
		}
	}
	notGrease := []uint16{0x0000, 0x1301, 0xc02f, 0x000d, 0x0a0b, 0x1a2a, 0xabab}
	for _, v := range notGrease {
		if isGREASE(v) {
			t.Errorf("isGREASE(0x%04x) = true, want false", v)
		}
	}
}

func TestGREASEIgnoredInCounts(t *testing.T) {
	ch := &ClientHello{
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x1302}, // one GREASE
		Extensions:        []uint16{0x1a1a, 0x0000, 0x002b}, // one GREASE
		SupportedVersions: []uint16{0x0a0a, 0x0304},         // GREASE + 1.3
		HasSNI:            true,
	}
	// 2 real ciphers, 2 real extensions (counts are chars 4..8: tVVd CC EE AA).
	if got := ch.JA4A(TransportTCP); got[4:8] != "0202" {
		t.Errorf("counts in %q = %q, want 0202", got, got[4:8])
	}
	if got := ch.version(); got != "13" {
		t.Errorf("version() = %q, want 13 (GREASE ignored)", got)
	}
}

func TestALPNChars(t *testing.T) {
	cases := []struct {
		alpn []string
		want string
	}{
		{nil, "00"},
		{[]string{""}, "00"},
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"x"}, "xx"},        // single char: first == last
		{[]string{"\x00"}, "00"},     // non-alnum -> hex of value: 0x00 -> "00"
		{[]string{"\xab"}, "ab"},     // 0xab -> "ab"
		{[]string{"\xab\xcd"}, "ad"}, // first+last hex nibble pair
		{[]string{"spdy/3"}, "s3"},   // alnum first/last
	}
	for _, c := range cases {
		if got := alpnChars(c.alpn); got != c.want {
			t.Errorf("alpnChars(%q) = %q, want %q", c.alpn, got, c.want)
		}
	}
}

func TestEmptyCipherAndExtHashes(t *testing.T) {
	ch := &ClientHello{HasSNI: false}
	ja4 := ch.JA4()
	// No ciphers and no extensions -> both hash sections are all-zero.
	wantSuffix := "_000000000000_000000000000"
	if ja4[len(ja4)-len(wantSuffix):] != wantSuffix {
		t.Errorf("JA4() = %q, want suffix %q", ja4, wantSuffix)
	}
}
