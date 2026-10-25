package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Transport identifies the first character of a JA4 fingerprint.
type Transport byte

const (
	TransportTCP  Transport = 't' // TLS over TCP
	TransportQUIC Transport = 'q' // QUIC
	TransportDTLS Transport = 'd' // DTLS
)

// isGREASE reports whether v is a GREASE value per RFC 8701: the 16 values
// 0x0a0a, 0x1a1a, ... 0xfafa (both bytes equal, low nibble of each is 0xa).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0x00ff
}

// tlsVersionCode maps a TLS/DTLS version number to its two-character JA4 code.
func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// version returns the two-character version code: the highest non-GREASE
// value from supported_versions if present, otherwise the legacy version.
func (ch *ClientHello) version() string {
	best := uint16(0)
	found := false
	for _, v := range ch.SupportedVersions {
		if isGREASE(v) {
			continue
		}
		// Compare by the real protocol ordering, not raw numeric value
		// (DTLS versions count down). For TLS-over-TCP the raw order is fine;
		// we rank by a normalized key.
		if !found || versionRank(v) > versionRank(best) {
			best = v
			found = true
		}
	}
	if found {
		return tlsVersionCode(best)
	}
	return tlsVersionCode(ch.LegacyVersion)
}

// versionRank orders versions so that "higher" means newer, covering both the
// ascending TLS codes and the descending DTLS codes.
func versionRank(v uint16) int {
	switch v {
	case 0xfefc: // DTLS 1.3
		return 0x0304
	case 0xfefd: // DTLS 1.2
		return 0x0303
	case 0xfeff: // DTLS 1.0
		return 0x0301
	default:
		return int(v)
	}
}

// alpnChars returns the two-character ALPN code for the first ALPN value,
// following the spec's alphanumeric / hex fallback rules.
func alpnChars(alpn []string) string {
	if len(alpn) == 0 || len(alpn[0]) == 0 {
		return "00"
	}
	v := alpn[0]
	first := v[0]
	last := v[len(v)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	// Non-alphanumeric: use first and last chars of the hex representation
	// of the whole first ALPN value.
	h := hex.EncodeToString([]byte(v))
	return string([]byte{h[0], h[len(h)-1]})
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func hex4(v uint16) string {
	return fmt.Sprintf("%04x", v)
}

func truncHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// filterGREASE returns the input with GREASE values removed.
func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// cipherList returns the non-GREASE ciphers as 4-hex strings in wire order.
func (ch *ClientHello) cipherList() []string {
	cs := filterGREASE(ch.CipherSuites)
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = hex4(c)
	}
	return out
}

// extListSorted returns the non-GREASE extensions as 4-hex strings, sorted,
// with SNI (0x0000) and ALPN (0x0010) removed (they are captured in JA4_a).
func (ch *ClientHello) extListSorted() []string {
	out := make([]string, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if isGREASE(e) || e == extServerName || e == extALPN {
			continue
		}
		out = append(out, hex4(e))
	}
	sort.Strings(out)
	return out
}

// sigAlgList returns the signature algorithms as 4-hex strings in wire order.
func (ch *ClientHello) sigAlgList() []string {
	sa := filterGREASE(ch.SignatureAlgorithms)
	out := make([]string, len(sa))
	for i, s := range sa {
		out[i] = hex4(s)
	}
	return out
}

func (ch *ClientHello) nonGREASECipherCount() int {
	return len(filterGREASE(ch.CipherSuites))
}

func (ch *ClientHello) nonGREASEExtCount() int {
	return len(filterGREASE(ch.Extensions))
}

func (ch *ClientHello) sniChar() string {
	if ch.HasSNI {
		return "d"
	}
	return "i"
}

// JA4A returns the first (human-readable) section of the fingerprint, e.g.
// "t13d3113h2".
func (ch *ClientHello) JA4A(t Transport) string {
	var b strings.Builder
	b.WriteByte(byte(t))
	b.WriteString(ch.version())
	b.WriteString(ch.sniChar())
	b.WriteString(count2(ch.nonGREASECipherCount()))
	b.WriteString(count2(ch.nonGREASEExtCount()))
	b.WriteString(alpnChars(ch.ALPN))
	return b.String()
}

// JA4 returns the full JA4 fingerprint over TCP, e.g.
// "t13d3113h2_e8f1e7e78f70_ce5650b735ce".
func (ch *ClientHello) JA4() string {
	return ch.JA4WithTransport(TransportTCP)
}

// JA4WithTransport returns the full JA4 fingerprint with an explicit transport.
func (ch *ClientHello) JA4WithTransport(t Transport) string {
	ciphers := ch.cipherList()
	var b string
	if len(ciphers) == 0 {
		b = "000000000000"
	} else {
		sorted := append([]string(nil), ciphers...)
		sort.Strings(sorted)
		b = truncHash(strings.Join(sorted, ","))
	}

	exts := ch.extListSorted()
	var c string
	if len(exts) == 0 {
		c = "000000000000"
	} else {
		s := strings.Join(exts, ",")
		if sa := ch.sigAlgList(); len(sa) > 0 {
			s += "_" + strings.Join(sa, ",")
		}
		c = truncHash(s)
	}

	return ch.JA4A(t) + "_" + b + "_" + c
}

// JA4Raw returns the raw (unhashed, sorted) form of the fingerprint: JA4_r.
func (ch *ClientHello) JA4Raw() string {
	return ch.JA4RawWithTransport(TransportTCP)
}

// JA4RawWithTransport returns JA4_r with an explicit transport.
func (ch *ClientHello) JA4RawWithTransport(t Transport) string {
	ciphers := append([]string(nil), ch.cipherList()...)
	sort.Strings(ciphers)

	exts := ch.extListSorted()

	parts := []string{ch.JA4A(t), strings.Join(ciphers, ","), strings.Join(exts, ",")}
	raw := strings.Join(parts, "_")
	if sa := ch.sigAlgList(); len(sa) > 0 {
		raw += "_" + strings.Join(sa, ",")
	}
	return raw
}
