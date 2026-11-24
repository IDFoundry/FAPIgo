package client

import "testing"

// ambiguousResponses are response bodies a strict parser and Go's
// encoding/json read differently: a repeated member (encoding/json keeps
// the last), a case variant of a member the client reads (encoding/json
// matches it case-insensitively), and data after the object (a
// json.Decoder stops after the first value). Each is built around
// valid, the same response stated once.
func ambiguousResponses(valid, member, value, otherValue string) map[string]string {
	inner := valid[1 : len(valid)-1]
	return map[string]string{
		"repeated member":         `{` + inner + `,"` + member + `":` + otherValue + `}`,
		"case variant alone":      `{` + replaceMember(inner, member) + `}`,
		"case variant beside it":  `{` + inner + `,"` + upper(member) + `":` + otherValue + `}`,
		"second object":           valid + `{"` + member + `":` + otherValue + `}`,
		"trailing garbage":        valid + `x`,
		"repeated nested member":  `{` + inner + `,"x":{"a":1,"a":2}}`,
		"case-variant nested one": `{` + inner + `,"x":{"a":1,"A":2}}`,
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// replaceMember renames member to its upper-case spelling in inner.
func replaceMember(inner, member string) string {
	quoted := `"` + member + `"`
	for i := 0; i+len(quoted) <= len(inner); i++ {
		if inner[i:i+len(quoted)] == quoted {
			return inner[:i] + `"` + upper(member) + `"` + inner[i+len(quoted):]
		}
	}
	panic("member not in response: " + member)
}

// TestDecodeTokenResponseRefusesAmbiguousResponses: a token response
// that a strict parser and encoding/json would read differently is
// refused, while one carrying an unrecognized member is still read
// (RFC 6749 §5.1).
func TestDecodeTokenResponseRefusesAmbiguousResponses(t *testing.T) {
	const valid = `{"access_token":"tok","token_type":"DPoP","expires_in":300}`
	if _, err := decodeTokenResponse([]byte(valid)); err != nil {
		t.Fatalf("decodeTokenResponse(valid) = %v", err)
	}
	for name, body := range ambiguousResponses(valid, "access_token", `"tok"`, `"other"`) {
		if got, err := decodeTokenResponse([]byte(body)); err == nil {
			t.Errorf("%s: decodeTokenResponse(%s) = %+v, want an error", name, body, got)
		}
	}
	for name, body := range ambiguousResponses(valid, "expires_in", `300`, `999999`) {
		if got, err := decodeTokenResponse([]byte(body)); err == nil {
			t.Errorf("expires_in %s: decodeTokenResponse(%s) = %+v, want an error", name, body, got)
		}
	}
}

// TestDecodeBackchannelAuthenticationResponseRefusesAmbiguousResponses
// is the same for a backchannel authentication response.
func TestDecodeBackchannelAuthenticationResponseRefusesAmbiguousResponses(t *testing.T) {
	const valid = `{"auth_req_id":"id-1","expires_in":120,"interval":5}`
	if _, err := decodeBackchannelAuthenticationResponse([]byte(valid)); err != nil {
		t.Fatalf("decodeBackchannelAuthenticationResponse(valid) = %v", err)
	}
	if _, err := decodeBackchannelAuthenticationResponse([]byte(`{"auth_req_id":"id-1","expires_in":120,"unexpected":"value"}`)); err != nil {
		t.Fatalf("decodeBackchannelAuthenticationResponse(unknown member) = %v, want it ignored", err)
	}
	for name, body := range ambiguousResponses(valid, "auth_req_id", `"id-1"`, `"id-2"`) {
		if got, err := decodeBackchannelAuthenticationResponse([]byte(body)); err == nil {
			t.Errorf("%s: decodeBackchannelAuthenticationResponse(%s) = %+v, want an error", name, body, got)
		}
	}
}
