package client

import "testing"

// TestDecodeTokenResponseIgnoresUnknownField covers RFC 6749 §5.1's
// "MUST ignore unrecognized value names and extra parameters received
// in the response" — a real authorization server routinely adds
// parameters this module has no reason to model (e.g.
// refresh_token_expires_in, authorization_details), and rejecting the
// whole response over one would break token exchange against any such
// server.
func TestDecodeTokenResponseIgnoresUnknownField(t *testing.T) {
	body := []byte(`{"access_token":"tok","token_type":"DPoP","expires_in":300,"unexpected":"value"}`)
	got, err := decodeTokenResponse(body)
	if err != nil {
		t.Fatalf("decodeTokenResponse(unknown field) = %v, want nil error", err)
	}
	if got.AccessToken != "tok" || got.TokenType != "DPoP" || got.ExpiresIn != 300 {
		t.Fatalf("decodeTokenResponse(unknown field) = %+v, want known fields still parsed", got)
	}
}
