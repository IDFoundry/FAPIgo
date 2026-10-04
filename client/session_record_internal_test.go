package client

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSessionRecordRoundTrip(t *testing.T) {
	seconds := int64(300)
	raw, err := encodeSessionRecord(sessionRecord{
		Nonce: "n", PKCEVerifier: "v", Issuer: "https://as.example", RedirectURI: "https://rp.example/cb",
		ResponseMode: responseModePlain, MaxAgeSeconds: &seconds,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSessionRecord(raw)
	if err != nil {
		t.Fatalf("decodeSessionRecord: %v", err)
	}
	if maxAge, ok := got.maxAge(); !ok || maxAge != 5*time.Minute || got.Nonce != "n" || got.RedirectURI != "https://rp.example/cb" {
		t.Errorf("round trip = %+v (max_age %v, %v)", got, maxAge, ok)
	}
	// A field a later version adds is ignored, for rolling deploys.
	if _, err := decodeSessionRecord(json.RawMessage(`{"v":1,"pkce_verifier":"v","issuer":"i","response_mode":"plain","later_field":true}`)); err != nil {
		t.Errorf("decodeSessionRecord(unknown field) = %v, want it ignored", err)
	}
}

func TestDecodeSessionRecordRefuses(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":                  ``,
		"not JSON":               `{`,
		"another version":        `{"v":2,"pkce_verifier":"v","issuer":"i","response_mode":"plain"}`,
		"no PKCE verifier":       `{"v":1,"issuer":"i","response_mode":"plain"}`,
		"no issuer":              `{"v":1,"pkce_verifier":"v","response_mode":"plain"}`,
		"no response mode":       `{"v":1,"pkce_verifier":"v","issuer":"i"}`,
		"negative max_age":       `{"v":1,"pkce_verifier":"v","issuer":"i","response_mode":"plain","max_age":-1}`,
		"max_age over 100 years": `{"v":1,"pkce_verifier":"v","issuer":"i","response_mode":"plain","max_age":9223372036}`,
	} {
		if _, err := decodeSessionRecord(json.RawMessage(raw)); err == nil {
			t.Errorf("decodeSessionRecord(%s) = nil error, want refusal", name)
		}
	}
}

func TestCheckAuthenticationAge(t *testing.T) {
	now := time.Now()
	if err := checkAuthenticationAge(now.Add(-5*time.Minute-3*time.Second), 5*time.Minute, now, 5*time.Second); err != nil {
		t.Errorf("within the clock skew allowance: %v", err)
	}
	if err := checkAuthenticationAge(now.Add(-5*time.Minute-6*time.Second), 5*time.Minute, now, 5*time.Second); err == nil {
		t.Error("past max_age and the skew: nil error, want refusal")
	}
}

// TestSessionRecordWithoutOpenIDField covers a record written before the
// openid field existed: it decodes, and doesn't require an ID token.
func TestSessionRecordWithoutOpenIDField(t *testing.T) {
	r, err := decodeSessionRecord([]byte(`{"v":1,"pkce_verifier":"v","issuer":"https://as.example","redirect_uri":"https://rp.example/cb","response_mode":"plain"}`))
	if err != nil || r.OpenID {
		t.Fatalf("decodeSessionRecord(old) = %+v, %v; want OpenID false", r, err)
	}
}

// TestRequireIDToken covers every case requireIDToken decides, including
// max_age without openid, which only a session record from before
// BeginAuthorization refused it can still carry.
func TestRequireIDToken(t *testing.T) {
	for _, tc := range []struct {
		hasIDToken, openID, hasMaxAge, wantErr bool
	}{
		{false, true, false, true},
		{false, false, true, true},
		{false, true, true, true},
		{false, false, false, false},
		{true, true, true, false},
		{true, false, false, false},
	} {
		if err := requireIDToken(tc.hasIDToken, tc.openID, tc.hasMaxAge); (err != nil) != tc.wantErr {
			t.Errorf("requireIDToken(%v, %v, %v) = %v, want error %v", tc.hasIDToken, tc.openID, tc.hasMaxAge, err, tc.wantErr)
		}
	}
}
