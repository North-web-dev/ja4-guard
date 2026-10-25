package ja4

import (
	"fmt"
	"sort"
	"strings"
)

// JA4H holds a parsed JA4H HTTP-client fingerprint.
type JA4H struct {
	// Value is the hashed fingerprint, e.g. "ge11cn20enus_<hdrs>_<ckf>_<ckv>".
	Value string
	// Raw is the unhashed (JA4H_r) form, useful for debugging and allow-lists.
	Raw string
}

// ja4hInput is the decoded view of one HTTP request that JA4H consumes.
type ja4hInput struct {
	method  string   // e.g. "GET"
	version string   // e.g. "11", "20"
	headers []string // header names in wire order, original case
	cookies []string // raw "name=value" cookie pairs
	hasCk   bool     // a Cookie header was present
	lang    string   // raw Accept-Language value, or "" if absent
}

// ComputeJA4H computes the JA4H fingerprint from a decoded request. Header
// names must be in wire order with their original case; cookies are the raw
// pairs from the Cookie header(s). This mirrors the FoxIO reference.
func computeJA4H(in ja4hInput) JA4H {
	method := strings.ToLower(in.method)
	if len(method) > 2 {
		method = method[:2]
	}

	cookieChar := "n"
	if in.hasCk {
		cookieChar = "c"
	}

	refererChar := "n"
	for _, h := range in.headers {
		if strings.EqualFold(h, "referer") {
			refererChar = "r"
			break
		}
	}

	// Header names, in order, excluding Cookie, Referer and HTTP/2 pseudo-
	// headers (those beginning with ':').
	var names []string
	for _, h := range in.headers {
		if strings.HasPrefix(h, ":") {
			continue
		}
		lh := strings.ToLower(h)
		if strings.HasPrefix(lh, "cookie") || lh == "referer" {
			continue
		}
		names = append(names, h)
	}
	headerLen := count2(len(names))

	lang := "0000"
	if in.lang != "" {
		l := strings.ToLower(in.lang)
		l = strings.ReplaceAll(l, "-", "")
		l = strings.ReplaceAll(l, ";", ",")
		if idx := strings.IndexByte(l, ','); idx >= 0 {
			l = l[:idx]
		}
		if len(l) > 4 {
			l = l[:4]
		}
		lang = l + strings.Repeat("0", 4-len(l))
	}

	// The FoxIO reference hashes the comma-joined header list directly, so an
	// empty list hashes the empty string rather than becoming all-zeros.
	headersHash := truncHash(strings.Join(names, ","))

	var ckFields, ckValues []string
	for _, c := range in.cookies {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		name := c
		if eq := strings.IndexByte(c, '='); eq >= 0 {
			name = strings.TrimSpace(c[:eq])
		}
		ckFields = append(ckFields, name)
		ckValues = append(ckValues, c)
	}
	// Sort cookie fields and values by field name.
	type pair struct{ field, value string }
	pairs := make([]pair, len(ckFields))
	for i := range ckFields {
		pairs[i] = pair{ckFields[i], ckValues[i]}
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].field < pairs[j].field })
	sortedFields := make([]string, len(pairs))
	sortedValues := make([]string, len(pairs))
	for i, p := range pairs {
		sortedFields[i] = p.field
		sortedValues[i] = p.value
	}

	cookiesHash := "000000000000"
	cookieValuesHash := "000000000000"
	if in.hasCk {
		cookiesHash = truncHash(strings.Join(sortedFields, ","))
		cookieValuesHash = truncHash(strings.Join(sortedValues, ","))
	}

	a := fmt.Sprintf("%s%s%s%s%s%s", method, in.version, cookieChar, refererChar, headerLen, lang)
	value := fmt.Sprintf("%s_%s_%s_%s", a, headersHash, cookiesHash, cookieValuesHash)

	raw := a + "_" + strings.Join(names, ",") + "_"
	if in.hasCk {
		raw += strings.Join(sortedFields, ",") + "_" + strings.Join(sortedValues, ",")
	}

	return JA4H{Value: value, Raw: raw}
}

// JA4HFromRequestHead parses a raw HTTP/1.x request header block (everything
// up to and including the terminating CRLFCRLF) and computes JA4H. It returns
// an error if the block is not a well-formed HTTP/1.x request head.
func JA4HFromRequestHead(head []byte) (JA4H, error) {
	text := string(head)
	// Normalize to find the end of the header section.
	if i := strings.Index(text, "\r\n\r\n"); i >= 0 {
		text = text[:i]
	} else if i := strings.Index(text, "\n\n"); i >= 0 {
		text = text[:i]
	}
	lines := splitLines(text)
	if len(lines) == 0 {
		return JA4H{}, fmt.Errorf("ja4h: empty request head")
	}

	reqLine := strings.Fields(lines[0])
	if len(reqLine) < 3 {
		return JA4H{}, fmt.Errorf("ja4h: malformed request line %q", lines[0])
	}
	in := ja4hInput{method: reqLine[0]}
	in.version = httpVersionCode(reqLine[2])
	// This function reconstructs JA4H from a raw byte stream, which only works
	// for HTTP/1.x. An "HTTP/2.0" request line here is the connection preface
	// (PRI * HTTP/2.0), not a real request, so reject it.
	if in.version == "20" || in.version == "30" {
		return JA4H{}, fmt.Errorf("ja4h: not an HTTP/1.x request head (%q)", reqLine[2])
	}

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		in.headers = append(in.headers, name)

		lname := strings.ToLower(name)
		switch {
		case lname == "cookie":
			in.hasCk = true
			for _, c := range strings.Split(value, ";") {
				if strings.TrimSpace(c) != "" {
					in.cookies = append(in.cookies, strings.TrimSpace(c))
				}
			}
		case lname == "accept-language" && in.lang == "":
			in.lang = value
		}
	}

	return computeJA4H(in), nil
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}

// httpVersionCode maps an HTTP version token ("HTTP/1.1") to its JA4H code.
func httpVersionCode(tok string) string {
	slash := strings.IndexByte(tok, '/')
	if slash < 0 {
		return "11"
	}
	ver := tok[slash+1:]
	ver = strings.ReplaceAll(ver, ".", "")
	switch ver {
	case "10":
		return "10"
	case "11":
		return "11"
	case "2", "20":
		return "20"
	case "3", "30":
		return "30"
	default:
		if ver == "" {
			return "11"
		}
		return ver
	}
}
