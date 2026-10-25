package ja4

import "testing"

func TestJA4HVectors(t *testing.T) {
	cases := []struct {
		name string
		head string
		want string
		raw  string
	}{
		{
			// Values produced by the FoxIO reference ja4h.py for this request.
			name: "cookies+lang+referer",
			head: "GET /index.html HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"User-Agent: curl/7.81.0\r\n" +
				"Accept: */*\r\n" +
				"Accept-Language: en-US,en;q=0.9\r\n" +
				"Cookie: a=1; b=2\r\n" +
				"Referer: http://example.org/\r\n\r\n",
			want: "ge11cr04enus_8ddaef5d77af_1eb7c54d5283_06beefe2b477",
			raw:  "ge11cr04enus_Host,User-Agent,Accept,Accept-Language_a,b_a=1,b=2",
		},
		{
			// No cookies, no Accept-Language, POST.
			name: "post-minimal",
			head: "POST /submit HTTP/1.1\r\n" +
				"Host: api.test\r\n" +
				"User-Agent: Go-http-client/1.1\r\n" +
				"Accept-Encoding: gzip\r\n\r\n",
			want: "po11nn030000_cd680697de12_000000000000_000000000000",
			raw:  "po11nn030000_Host,User-Agent,Accept-Encoding_",
		},
		{
			// Real curl --http1.1 request captured live during the build.
			name: "curl-http1.1-live",
			head: "GET / HTTP/1.1\r\n" +
				"Host: curl.ja4.test:18443\r\n" +
				"User-Agent: curl/7.81.0\r\n" +
				"Accept: */*\r\n" +
				"Cookie: sid=abc; theme=dark\r\n" +
				"Accept-Language: en-US,en;q=0.9\r\n\r\n",
			want: "ge11cn04enus_8ddaef5d77af_1777f707f29d_d88f81fbfec9",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := JA4HFromRequestHead([]byte(c.head))
			if err != nil {
				t.Fatalf("JA4HFromRequestHead: %v", err)
			}
			if h.Value != c.want {
				t.Errorf("JA4H = %q, want %q", h.Value, c.want)
			}
			if c.raw != "" && h.Raw != c.raw {
				t.Errorf("JA4H_r = %q, want %q", h.Raw, c.raw)
			}
		})
	}
}

func TestJA4HRejectsHTTP2Preface(t *testing.T) {
	// The HTTP/2 connection preface is not a real request head.
	_, err := JA4HFromRequestHead([]byte("PRI * HTTP/2.0\r\n\r\n"))
	if err == nil {
		t.Fatal("expected error for HTTP/2 preface")
	}
}

func TestJA4HMalformed(t *testing.T) {
	if _, err := JA4HFromRequestHead([]byte("")); err == nil {
		t.Error("expected error for empty head")
	}
	if _, err := JA4HFromRequestHead([]byte("garbage\r\n\r\n")); err == nil {
		t.Error("expected error for malformed request line")
	}
}
