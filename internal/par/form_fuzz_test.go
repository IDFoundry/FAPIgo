package par

import (
	"strings"
	"testing"
)

// FuzzDecodeForm exercises DecodeForm against arbitrary bytes — a PAR
// request body is client-supplied, form-encoded, and parsed before any
// other check runs. Exercises the duplicate-parameter rejection
// (DecodeForm's own doc comment: resolving a duplicate by picking the
// first or last occurrence would make it a request-smuggling
// primitive) and the size ceiling, on top of net/url's own query-string
// parsing. Only checks for panics/hangs.
func FuzzDecodeForm(f *testing.F) {
	f.Add(EncodeForm(map[string]string{"client_id": "https://client.example", "response_type": "code"}))
	f.Add(EncodeForm(nil))
	f.Add([]byte("a=1&a=2"))
	f.Add([]byte("a=%zz"))
	f.Add([]byte("=&=&="))
	f.Add([]byte(""))
	f.Add([]byte(strings.Repeat("a=1&", 20000)))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeForm(body)
	})
}
