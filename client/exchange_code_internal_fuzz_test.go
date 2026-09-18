package client

import "testing"

// FuzzDecodeTokenResponse exercises decodeTokenResponse against
// arbitrary bytes — the authorization server's own token endpoint
// response body, the single richest piece of AS-controlled data a
// client parses (access_token, id_token, refresh_token,
// authorization_details), deliberately tolerant of unrecognized
// members per RFC 6749 §5.1. Unexported, so this file lives in package
// client rather than client_test, the same convention this repo's own
// *_internal_test.go files already use. Only checks for panics/hangs.
func FuzzDecodeTokenResponse(f *testing.F) {
	f.Add([]byte(`{"access_token":"fuzz-at","token_type":"Bearer","expires_in":3600}`))
	f.Add([]byte(`{"access_token":"fuzz-at","token_type":"DPoP","expires_in":3600,"id_token":"a.b.c","refresh_token":"fuzz-rt","scope":"openid","authorization_details":[{"type":"payment_initiation"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"access_token":"","token_type":"Bearer","expires_in":3600}`))
	f.Add([]byte(`{"access_token":"fuzz-at","token_type":"","expires_in":3600}`))
	f.Add([]byte(`{"access_token":"fuzz-at","token_type":"Bearer","expires_in":-1}`))
	f.Add([]byte(`{"access_token":"fuzz-at","token_type":"Bearer","expires_in":3600,"unexpected":"field"}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = decodeTokenResponse(body)
	})
}
