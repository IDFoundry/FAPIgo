package client

import "testing"

// FuzzDecodeBackchannelAuthenticationResponse exercises
// decodeBackchannelAuthenticationResponse against arbitrary bytes — the
// authorization server's own CIBA backchannel authentication endpoint
// response body, deliberately tolerant of unrecognized members per RFC
// 6749 §5.1, the same reasoning decodeTokenResponse applies. Unexported,
// so this file lives in package client rather than client_test. Only
// checks for panics/hangs.
func FuzzDecodeBackchannelAuthenticationResponse(f *testing.F) {
	f.Add([]byte(`{"auth_req_id":"fuzz-req-id","expires_in":120}`))
	f.Add([]byte(`{"auth_req_id":"fuzz-req-id","expires_in":120,"interval":5}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"auth_req_id":"","expires_in":120}`))
	f.Add([]byte(`{"auth_req_id":"fuzz-req-id","expires_in":0}`))
	f.Add([]byte(`{"auth_req_id":"fuzz-req-id","expires_in":120,"interval":-1}`))
	f.Add([]byte(`{"auth_req_id":"fuzz-req-id","expires_in":120,"unexpected":"field"}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = decodeBackchannelAuthenticationResponse(body)
	})
}
