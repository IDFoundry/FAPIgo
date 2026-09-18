package par

import (
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzFormRoundTrip checks that DecodeForm(EncodeForm(params)) recovers
// params exactly, for any set of fuzzed key/value pairs. EncodeForm's
// own callers build params from a fixed, known set of OAuth parameter
// names, so this isn't attacker-facing the way DecodeForm's own
// (already fuzzed) parsing of an inbound body is — but a round-trip
// bug here would corrupt an outbound PAR request body regardless, and
// go's url.Values percent-encoding has enough edge cases (an empty key,
// "=" or "&" inside a value, non-ASCII bytes) that this is worth
// checking beyond the package's existing example-based unit tests.
func FuzzFormRoundTrip(f *testing.F) {
	f.Add("client_id", "s6BhdRkqt3", "redirect_uri", "https://client.example/cb", "state", "af0ifjsldkj")
	f.Add("", "", "a=b&c", "d=e&f", "g", "")
	f.Add("dup", "one", "dup", "two", "x", "y")

	f.Fuzz(func(t *testing.T, k1, v1, k2, v2, k3, v3 string) {
		params := map[string]string{}
		for _, kv := range [][2]string{{k1, v1}, {k2, v2}, {k3, v3}} {
			params[kv[0]] = kv[1]
		}

		encoded := EncodeForm(params)
		decoded, err := DecodeForm(encoded)
		if err != nil {
			t.Fatalf("DecodeForm(EncodeForm(%v)) = %v, %v", params, decoded, err)
		}
		if len(decoded) != len(params) {
			t.Fatalf("round-trip length mismatch: got %v, want %v", decoded, params)
		}
		for k, v := range params {
			if decoded[k] != v {
				t.Fatalf("round-trip mismatch for key %q: got %q, want %q", k, decoded[k], v)
			}
		}
	})
}

// FuzzResultRoundTrip checks that DecodeResult(EncodeResult(r))
// recovers r exactly for any valid PushResult — ExpiresIn is
// constructed from whole seconds so the lossy division EncodeResult
// itself does (nanoseconds truncated to whole seconds on the wire,
// RFC 9126's own granularity) doesn't produce a spurious mismatch.
// RequestURI is required to be valid UTF-8: encoding/json.Marshal
// itself replaces an invalid UTF-8 byte with U+FFFD when producing a
// JSON string, a lossy transformation inherent to JSON (which must be
// valid Unicode text) rather than a round-trip bug in this package —
// found by this exact target's first fuzzing run, which is why the
// guard is here and not just asserted in a comment. A RequestURI long
// enough to push the encoded body past DecodeResult's own
// maxResponseBytes ceiling is skipped too, for the same reason: that
// ceiling exists specifically to reject an oversized body regardless of
// validity, so a round-trip failure there is DecodeResult doing its
// job, not a bug.
func FuzzResultRoundTrip(f *testing.F) {
	f.Add("urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c", int64(90))
	f.Add("a", int64(1))

	f.Fuzz(func(t *testing.T, requestURI string, seconds int64) {
		if requestURI == "" || seconds <= 0 || !utf8.ValidString(requestURI) {
			return
		}
		r := PushResult{RequestURI: requestURI, ExpiresIn: time.Duration(seconds) * time.Second}

		body, err := EncodeResult(r)
		if err != nil {
			t.Fatalf("EncodeResult(%+v): %v", r, err)
		}
		if len(body) > maxResponseBytes {
			return
		}
		decoded, err := DecodeResult(body)
		if err != nil {
			t.Fatalf("DecodeResult(EncodeResult(%+v)) = %v, %v", r, decoded, err)
		}
		if decoded != r {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, r)
		}
	})
}

// FuzzErrorResponseRoundTrip checks that
// DecodeErrorResponse(EncodeErrorResponse(e)) recovers e exactly for
// any ErrorResponse with a non-empty, valid-UTF-8 Code — see
// FuzzResultRoundTrip's own doc comment for why invalid UTF-8 and an
// encoded body past maxResponseBytes are both excluded (JSON/size
// properties, not round-trip bugs).
func FuzzErrorResponseRoundTrip(f *testing.F) {
	f.Add("invalid_request", "a human-readable description", "https://as.example/errors/1")
	f.Add("server_error", "", "")

	f.Fuzz(func(t *testing.T, code, description, uri string) {
		if code == "" || !utf8.ValidString(code) || !utf8.ValidString(description) || !utf8.ValidString(uri) {
			return
		}
		e := ErrorResponse{Code: code, Description: description, URI: uri}

		body, err := EncodeErrorResponse(e)
		if err != nil {
			t.Fatalf("EncodeErrorResponse(%+v): %v", e, err)
		}
		if len(body) > maxResponseBytes {
			return
		}
		decoded, err := DecodeErrorResponse(body)
		if err != nil {
			t.Fatalf("DecodeErrorResponse(EncodeErrorResponse(%+v)) = %v, %v", e, decoded, err)
		}
		if decoded != e {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, e)
		}
	})
}
