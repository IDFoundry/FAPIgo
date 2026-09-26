package server

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestGrantRecordRoundTrips(t *testing.T) {
	want := grantRecord{
		RedirectURI: "https://rp.example/cb", CodeChallenge: "challenge", Nonce: "n",
		DPoPJKT: "jkt", Subject: "user-1", Scope: []string{"openid", "accounts"},
		AuthTime: time.Unix(1_700_000_000, 0).UTC(), ACR: "acr-1", AMR: []string{"pwd"},
		AuthorizationDetails:    json.RawMessage(`[{"type":"payment"}]`),
		TokenClaims:             map[string]json.RawMessage{"x_hint": json.RawMessage(`"v"`)},
		RequestedIDTokenClaims:  []string{"name"},
		RequestedUserinfoClaims: []string{"email"},
	}
	raw, err := encodeGrantRecord(want)
	if err != nil {
		t.Fatalf("encodeGrantRecord: %v", err)
	}
	got, err := decodeGrantRecord(raw)
	if err != nil {
		t.Fatalf("decodeGrantRecord: %v", err)
	}
	want.Version = recordVersion
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestRequestRecordRoundTrips(t *testing.T) {
	want := requestRecord{
		Parameters:  map[string]json.RawMessage{"scope": json.RawMessage(`"openid"`)},
		TokenClaims: map[string]json.RawMessage{"x_hint": json.RawMessage(`"v"`)},
		DPoPJKT:     "jkt",
	}
	raw, err := encodeRequestRecord(want)
	if err != nil {
		t.Fatalf("encodeRequestRecord: %v", err)
	}
	got, err := decodeRequestRecord(raw)
	if err != nil {
		t.Fatalf("decodeRequestRecord: %v", err)
	}
	want.Version = recordVersion
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

// TestDecodeGrantRecordIgnoresUnknownFields covers a rolling deploy: a
// record written by a newer server with an extra field must still be
// readable by an older one.
func TestDecodeGrantRecordIgnoresUnknownFields(t *testing.T) {
	got, err := decodeGrantRecord(json.RawMessage(`{"v":1,"sub":"user-1","added_later":{"x":1}}`))
	if err != nil {
		t.Fatalf("decodeGrantRecord: %v", err)
	}
	if got.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", got.Subject)
	}
}

func TestDecodeRecordRejectsUnreadableInput(t *testing.T) {
	cases := map[string]json.RawMessage{
		"empty":           nil,
		"malformed":       json.RawMessage(`{"v":1,`),
		"missing version": json.RawMessage(`{"sub":"user-1"}`),
		"future version":  json.RawMessage(`{"v":2,"sub":"user-1"}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeGrantRecord(raw); err == nil {
				t.Fatalf("decodeGrantRecord(%s) = nil error, want error", raw)
			}
			if _, err := decodeRequestRecord(raw); err == nil {
				t.Fatalf("decodeRequestRecord(%s) = nil error, want error", raw)
			}
		})
	}
}

func TestGrantRecordForRefreshTokenDropsCodeOnlyFields(t *testing.T) {
	g := grantRecord{
		RedirectURI: "https://rp.example/cb", CodeChallenge: "challenge", Nonce: "n",
		DPoPJKT: "jkt", Subject: "user-1", Scope: []string{"openid", "offline_access"},
	}
	got := g.forRefreshToken("thumb-1")
	if got.RedirectURI != "" || got.CodeChallenge != "" || got.Nonce != "" {
		t.Fatalf("forRefreshToken kept code-only fields: %+v", got)
	}
	if got.Thumbprint != "thumb-1" || got.Subject != "user-1" || got.DPoPJKT != "jkt" || len(got.Scope) != 2 {
		t.Fatalf("forRefreshToken = %+v, want grant carried forward with thumbprint", got)
	}
}

// TestEncodeRecordsRejectInvalidUTF8 covers the backstop behind the
// app-facing constructors: a record json.Marshal would silently alter
// is refused rather than stored.
func TestEncodeRecordsRejectInvalidUTF8(t *testing.T) {
	grants := map[string]grantRecord{
		"subject":         {Subject: "user\xff"},
		"scope":           {Subject: "u", Scope: []string{"openid\xff"}},
		"amr":             {Subject: "u", AMR: []string{"pwd\xff"}},
		"token claim key": {Subject: "u", TokenClaims: map[string]json.RawMessage{"k\xff": json.RawMessage(`1`)}},
		"id token key":    {Subject: "u", IDTokenClaims: map[string]json.RawMessage{"k\xff": json.RawMessage(`1`)}},
	}
	for name, g := range grants {
		if _, err := encodeGrantRecord(g); err == nil {
			t.Errorf("encodeGrantRecord(invalid UTF-8 %s) = nil error, want error", name)
		}
	}
	if _, err := encodeRequestRecord(requestRecord{Parameters: map[string]json.RawMessage{"p\xff": json.RawMessage(`"x"`)}}); err == nil {
		t.Errorf("encodeRequestRecord(invalid UTF-8 parameter name) = nil error, want error")
	}
}
