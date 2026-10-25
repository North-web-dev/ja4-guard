// Package ja4 implements the JA4 (TLS client) and JA4H (HTTP client)
// fingerprints as defined by the FoxIO JA4 specification:
//
//	https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//	https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md
//
// The implementation is a clean-room reimplementation from the public spec.
// JA4 is not a FoxIO trademark of this project; see NOTICE in the spec repo
// for FoxIO's licensing of their own reference implementation.
package ja4

import (
	"errors"
	"fmt"
	"io"
)

// Handshake / record constants.
const (
	recordTypeHandshake   = 0x16
	handshakeTypeClientHl = 0x01

	extServerName          = 0x0000
	extALPN                = 0x0010
	extSupportedVersions   = 0x002b
	extSignatureAlgorithms = 0x000d
)

// ErrNotClientHello is returned when the bytes do not start with a TLS
// handshake record carrying a ClientHello.
var ErrNotClientHello = errors.New("ja4: not a TLS ClientHello")

// ClientHello holds the fields of a parsed TLS ClientHello that JA4 needs.
// Cipher suites and extensions are kept in wire order; GREASE values are
// retained here and filtered during fingerprint computation.
type ClientHello struct {
	LegacyVersion       uint16
	CipherSuites        []uint16
	Extensions          []uint16
	SupportedVersions   []uint16 // from extension 0x002b, in wire order
	SignatureAlgorithms []uint16 // from extension 0x000d, in wire order
	ALPN                []string // from extension 0x0010, in wire order
	ServerName          string   // from extension 0x0000 (host_name)
	HasSNI              bool
}

// byteReader is a minimal cursor over a byte slice with bounds checking.
type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) remaining() int { return len(r.b) - r.i }

func (r *byteReader) u8() (uint8, bool) {
	if r.remaining() < 1 {
		return 0, false
	}
	v := r.b[r.i]
	r.i++
	return v, true
}

func (r *byteReader) u16() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	v := uint16(r.b[r.i])<<8 | uint16(r.b[r.i+1])
	r.i += 2
	return v, true
}

func (r *byteReader) u24() (uint32, bool) {
	if r.remaining() < 3 {
		return 0, false
	}
	v := uint32(r.b[r.i])<<16 | uint32(r.b[r.i+1])<<8 | uint32(r.b[r.i+2])
	r.i += 3
	return v, true
}

func (r *byteReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.remaining() < n {
		return nil, false
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v, true
}

// ReadClientHello reads one or more TLS records from r, reassembles the
// ClientHello handshake message, and parses it. It returns the raw bytes it
// consumed from r (so a caller can replay them to a real TLS server) and the
// parsed ClientHello.
func ReadClientHello(r io.Reader) (consumed []byte, ch *ClientHello, err error) {
	var handshake []byte

	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return consumed, nil, err
		}
		consumed = append(consumed, hdr...)
		if hdr[0] != recordTypeHandshake {
			return consumed, nil, ErrNotClientHello
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen == 0 || recLen > 1<<16 {
			return consumed, nil, ErrNotClientHello
		}
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return consumed, nil, err
		}
		consumed = append(consumed, payload...)
		handshake = append(handshake, payload...)

		// Peek the handshake header once we have at least 4 bytes.
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != handshakeTypeClientHl {
			return consumed, nil, ErrNotClientHello
		}
		hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if len(handshake) >= 4+hsLen {
			handshake = handshake[:4+hsLen]
			break
		}
		// Need more records to complete the handshake message.
	}

	ch, err = ParseClientHello(handshake)
	return consumed, ch, err
}

// ParseClientHello parses a complete ClientHello handshake message (starting
// with the 1-byte handshake type and 3-byte length).
func ParseClientHello(handshake []byte) (*ClientHello, error) {
	br := &byteReader{b: handshake}

	htype, ok := br.u8()
	if !ok || htype != handshakeTypeClientHl {
		return nil, ErrNotClientHello
	}
	if _, ok := br.u24(); !ok { // handshake length
		return nil, ErrNotClientHello
	}

	ch := &ClientHello{}

	v, ok := br.u16()
	if !ok {
		return nil, fmt.Errorf("ja4: short ClientHello (legacy version)")
	}
	ch.LegacyVersion = v

	if _, ok := br.bytes(32); !ok { // random
		return nil, fmt.Errorf("ja4: short ClientHello (random)")
	}

	sidLen, ok := br.u8()
	if !ok {
		return nil, fmt.Errorf("ja4: short ClientHello (session id len)")
	}
	if _, ok := br.bytes(int(sidLen)); !ok {
		return nil, fmt.Errorf("ja4: short ClientHello (session id)")
	}

	csLen, ok := br.u16()
	if !ok {
		return nil, fmt.Errorf("ja4: short ClientHello (cipher len)")
	}
	csBytes, ok := br.bytes(int(csLen))
	if !ok || csLen%2 != 0 {
		return nil, fmt.Errorf("ja4: bad cipher list")
	}
	csr := &byteReader{b: csBytes}
	for csr.remaining() >= 2 {
		c, _ := csr.u16()
		ch.CipherSuites = append(ch.CipherSuites, c)
	}

	compLen, ok := br.u8()
	if !ok {
		return nil, fmt.Errorf("ja4: short ClientHello (compression len)")
	}
	if _, ok := br.bytes(int(compLen)); !ok {
		return nil, fmt.Errorf("ja4: short ClientHello (compression)")
	}

	// Extensions are optional (absent in very old ClientHellos).
	if br.remaining() == 0 {
		return ch, nil
	}
	extTotal, ok := br.u16()
	if !ok {
		return nil, fmt.Errorf("ja4: short ClientHello (extensions len)")
	}
	extBytes, ok := br.bytes(int(extTotal))
	if !ok {
		return nil, fmt.Errorf("ja4: bad extensions block")
	}
	if err := ch.parseExtensions(extBytes); err != nil {
		return nil, err
	}
	return ch, nil
}

func (ch *ClientHello) parseExtensions(b []byte) error {
	er := &byteReader{b: b}
	for er.remaining() >= 4 {
		etype, _ := er.u16()
		elen, _ := er.u16()
		edata, ok := er.bytes(int(elen))
		if !ok {
			return fmt.Errorf("ja4: truncated extension 0x%04x", etype)
		}
		ch.Extensions = append(ch.Extensions, etype)

		switch etype {
		case extServerName:
			ch.parseSNI(edata)
		case extALPN:
			ch.parseALPN(edata)
		case extSupportedVersions:
			ch.parseSupportedVersions(edata)
		case extSignatureAlgorithms:
			ch.parseSigAlgs(edata)
		}
	}
	return nil
}

func (ch *ClientHello) parseSNI(b []byte) {
	// ServerNameList: 2-byte list length, then entries of
	// {1-byte name_type, 2-byte length, name}. host_name is type 0.
	r := &byteReader{b: b}
	listLen, ok := r.u16()
	if !ok {
		return
	}
	inner := &byteReader{b: b[r.i:]}
	if int(listLen) <= inner.remaining() {
		inner.b = inner.b[:listLen]
	}
	for inner.remaining() >= 3 {
		nt, _ := inner.u8()
		nlen, _ := inner.u16()
		name, ok := inner.bytes(int(nlen))
		if !ok {
			return
		}
		if nt == 0 { // host_name
			ch.HasSNI = true
			ch.ServerName = string(name)
			return
		}
	}
	// An empty but present SNI extension still marks a domain destination.
	ch.HasSNI = true
}

func (ch *ClientHello) parseALPN(b []byte) {
	// ProtocolNameList: 2-byte list length, then {1-byte len, name} entries.
	r := &byteReader{b: b}
	if _, ok := r.u16(); !ok {
		return
	}
	for r.remaining() >= 1 {
		l, _ := r.u8()
		name, ok := r.bytes(int(l))
		if !ok {
			return
		}
		ch.ALPN = append(ch.ALPN, string(name))
	}
}

func (ch *ClientHello) parseSupportedVersions(b []byte) {
	// 1-byte list length, then 2-byte versions.
	r := &byteReader{b: b}
	if _, ok := r.u8(); !ok {
		return
	}
	for r.remaining() >= 2 {
		v, _ := r.u16()
		ch.SupportedVersions = append(ch.SupportedVersions, v)
	}
}

func (ch *ClientHello) parseSigAlgs(b []byte) {
	// 2-byte list length, then 2-byte algorithms.
	r := &byteReader{b: b}
	if _, ok := r.u16(); !ok {
		return
	}
	for r.remaining() >= 2 {
		v, _ := r.u16()
		ch.SignatureAlgorithms = append(ch.SignatureAlgorithms, v)
	}
}
