package par

import "testing"

// FuzzDecodeResult exercises DecodeResult against arbitrary bytes — a
// PAR endpoint's success response body, parsed client-side. Tolerant of
// unrecognized fields by design (see DecodeResult's own doc comment for
// why), unlike DecodeForm's own strict duplicate-parameter rejection.
// Only checks for panics/hangs.
func FuzzDecodeResult(f *testing.F) {
	valid, err := EncodeResult(PushResult{RequestURI: "urn:ietf:params:oauth:request_uri:fuzz", ExpiresIn: 60})
	if err != nil {
		f.Fatalf("EncodeResult: %v", err)
	}

	f.Add(valid)
	f.Add([]byte(`{"request_uri":"urn:...","expires_in":60,"unexpected":"field"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"request_uri":"","expires_in":60}`))
	f.Add([]byte(`{"request_uri":"urn:...","expires_in":0}`))
	f.Add([]byte(`{"request_uri":"urn:...","expires_in":-1}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeResult(body)
	})
}

// FuzzDecodeErrorResponse exercises DecodeErrorResponse against
// arbitrary bytes — a PAR endpoint's error response body (RFC 6749
// §5.2), parsed client-side, likewise tolerant of unrecognized fields.
// Only checks for panics/hangs.
func FuzzDecodeErrorResponse(f *testing.F) {
	valid, err := EncodeErrorResponse(ErrorResponse{Code: "invalid_request", Description: "fuzz description", URI: "https://as.example/errors/invalid_request"})
	if err != nil {
		f.Fatalf("EncodeErrorResponse: %v", err)
	}

	f.Add(valid)
	f.Add([]byte(`{"error":"invalid_request","unexpected":"field"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"error":""}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeErrorResponse(body)
	})
}
