package server

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
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
	issued := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	got := g.forRefreshToken(refreshBinding{Thumbprint: "thumb-1", InstanceKey: "instance-1"}, issued)
	if got.RedirectURI != "" || got.CodeChallenge != "" || got.Nonce != "" {
		t.Fatalf("forRefreshToken kept code-only fields: %+v", got)
	}
	if got.Kind != grantKindRefreshToken {
		t.Fatalf("forRefreshToken Kind = %q, want %q", got.Kind, grantKindRefreshToken)
	}
	if got.IssuedAt == nil || !got.IssuedAt.Equal(issued) {
		t.Fatalf("forRefreshToken IssuedAt = %v, want %v", got.IssuedAt, issued)
	}
	if got.Thumbprint != "thumb-1" || got.ClientInstanceKey != "instance-1" || got.Subject != "user-1" || got.DPoPJKT != "jkt" || len(got.Scope) != 2 {
		t.Fatalf("forRefreshToken = %+v, want grant carried forward with thumbprint and instance key", got)
	}
}

// TestGrantRecordIsKind covers which redemption accepts which record: a
// record's own kind only, and, for a record written before records
// carried a kind, a refresh token or CIBA grant only when it has none
// of an authorization code's fields, and an authorization code never.
func TestGrantRecordIsKind(t *testing.T) {
	legacyCode := grantRecord{RedirectURI: "https://rp.example/cb", CodeChallenge: "challenge", Nonce: "n"}
	tests := []struct {
		name   string
		record grantRecord
		accept map[grantKind]bool
	}{
		{"authorization code", grantRecord{Kind: grantKindAuthorizationCode}, map[grantKind]bool{grantKindAuthorizationCode: true}},
		{"refresh token", grantRecord{Kind: grantKindRefreshToken}, map[grantKind]bool{grantKindRefreshToken: true}},
		{"CIBA grant", grantRecord{Kind: grantKindBackchannel}, map[grantKind]bool{grantKindBackchannel: true}},
		{"unknown kind", grantRecord{Kind: "other"}, map[grantKind]bool{}},
		{"kind-less refresh token or CIBA grant", grantRecord{Subject: "user-1"}, map[grantKind]bool{grantKindRefreshToken: true, grantKindBackchannel: true}},
		{"kind-less authorization code", legacyCode, map[grantKind]bool{}},
		{"kind-less record with only a redirect_uri", grantRecord{RedirectURI: "https://rp.example/cb"}, map[grantKind]bool{}},
		{"kind-less record with only a PKCE challenge", grantRecord{CodeChallenge: "challenge"}, map[grantKind]bool{}},
		{"kind-less record with only a nonce", grantRecord{Nonce: "n"}, map[grantKind]bool{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, kind := range []grantKind{grantKindAuthorizationCode, grantKindRefreshToken, grantKindBackchannel} {
				if got := tt.record.isKind(kind); got != tt.accept[kind] {
					t.Errorf("isKind(%q) = %v, want %v", kind, got, tt.accept[kind])
				}
			}
		})
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

func TestIssuedWithin(t *testing.T) {
	issued := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		issuedAt *time.Time
		now      time.Time
		want     bool
	}{
		"inside the lifetime":             {&issued, issued.Add(9 * time.Minute), true},
		"at the end of the lifetime":      {&issued, issued.Add(10 * time.Minute), false},
		"past it":                         {&issued, issued.Add(time.Hour), false},
		"no issue time (an older record)": {nil, issued.Add(time.Hour), true},
	} {
		if got := issuedWithin(tc.issuedAt, 10*time.Minute, tc.now); got != tc.want {
			t.Errorf("%s: issuedWithin = %v, want %v", name, got, tc.want)
		}
	}
}

// TestOwnsRecord covers which records a server treats as its own: one
// stamped with its issuer, never one another issuer's server wrote or
// one written before records carried an issuer.
func TestOwnsRecord(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{Issuer: issuer}}
	for recorded, want := range map[string]bool{
		"https://as.example.com":       true,
		"":                             false,
		"https://tenant-b.example.com": false,
		"https://as.example.com/":      false,
	} {
		if got := s.ownsRecord(recorded); got != want {
			t.Errorf("ownsRecord(%q) = %v, want %v", recorded, got, want)
		}
	}

	stamped, err := s.encodeGrantRecord(grantRecord{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if g, err := decodeGrantRecord(stamped); err != nil || g.Issuer != issuer.String() {
		t.Errorf("encodeGrantRecord stamped issuer %q (err %v), want %q", g.Issuer, err, issuer.String())
	}
	request, err := s.encodeRequestRecord(requestRecord{})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := decodeRequestRecord(request); err != nil || r.Issuer != issuer.String() {
		t.Errorf("encodeRequestRecord stamped issuer %q (err %v), want %q", r.Issuer, err, issuer.String())
	}
	legacy, err := decodeGrantRecord([]byte(`{"v":1,"sub":"user-1","auth_time":"2026-01-01T00:00:00Z"}`))
	if err != nil || legacy.Issuer != "" || s.ownsRecord(legacy.Issuer) {
		t.Errorf("a record without an issuer: Issuer %q, err %v; want refused", legacy.Issuer, err)
	}
	if _, err := s.decodeOwnGrantRecord([]byte(`{"v":1,"sub":"user-1","auth_time":"2026-01-01T00:00:00Z"}`)); !errors.Is(err, errForeignRecord) {
		t.Errorf("decodeOwnGrantRecord(no issuer) = %v, want errForeignRecord", err)
	}
	if _, err := s.decodeOwnRequestRecord([]byte(`{"v":1,"parameters":{}}`)); !errors.Is(err, errForeignRecord) {
		t.Errorf("decodeOwnRequestRecord(no issuer) = %v, want errForeignRecord", err)
	}
}
