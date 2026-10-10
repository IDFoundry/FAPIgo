package client_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// sealingClient is an OAuthOnly client of testIssuer with clientID.
func sealingClient(t *testing.T, clientID fapi.ClientID) *client.Client {
	t.Helper()
	cfg, d := validConfig(t), validDependencies(t)
	oauthOnly(&cfg, &d)
	cfg.ClientID = clientID
	c, err := client.New(cfg, d)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

func sealKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i) // distinct bytes: a single repeated byte is refused
	}
	return k
}

// fullTokenSet is a TokenSet with every field set, as a code exchange
// with an ID token and a refresh token would return it.
func fullTokenSet() client.TokenSet {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	return client.TokenSet{
		AccessToken: fapi.NewSecret("at-1"), TokenType: "DPoP", Scope: "openid accounts",
		AuthorizationDetails: json.RawMessage(`[{"type":"account_information"}]`),
		ExpiresIn:            5 * time.Minute, HasExpiresIn: true, ObtainedAt: at,
		IDToken: fapi.NewSecret("id-token-1"), HasIDToken: true, Subject: "user-1",
		IDTokenClaims: client.IDTokenClaims{
			Subject: "user-1", AuthTime: at.Add(-time.Minute), ACR: "urn:acr:2", AMR: []string{"pwd", "otp"},
			Parameters: map[string]json.RawMessage{"email": json.RawMessage(`"sam@example.com"`)},
			ExpiresAt:  at.Add(time.Hour), IssuedAt: at, Issuer: testIssuer, Audience: []string{"client-1"}, Nonce: "n-1", AZP: "client-1",
		},
		RefreshToken: fapi.NewSecret("rt-1"), HasRefreshToken: true,
		Issuer: testIssuer,
	}
}

// revealed is t with its secrets readable, for comparing token sets.
func revealed(t client.TokenSet) map[string]any {
	return map[string]any{
		"access": t.AccessToken.Reveal(), "type": t.TokenType, "scope": t.Scope, "details": string(t.AuthorizationDetails),
		"expiresIn": t.ExpiresIn, "hasExpiresIn": t.HasExpiresIn, "obtainedAt": t.ObtainedAt.UTC(),
		"id": t.IDToken.Reveal(), "hasID": t.HasIDToken, "sub": t.Subject, "claims": claimsWithUTC(t.IDTokenClaims),
		"refresh": t.RefreshToken.Reveal(), "hasRefresh": t.HasRefreshToken, "issuer": t.Issuer,
	}
}

func claimsWithUTC(c client.IDTokenClaims) client.IDTokenClaims {
	c.AuthTime, c.ExpiresAt, c.IssuedAt = c.AuthTime.UTC(), c.ExpiresAt.UTC(), c.IssuedAt.UTC()
	return c
}

// sealer is a TokenSetSealer for an OAuthOnly client with clientID.
func sealer(t *testing.T, clientID fapi.ClientID, keys ...[]byte) *client.TokenSetSealer {
	t.Helper()
	s, err := client.NewTokenSetSealer(sealingClient(t, clientID), keys)
	if err != nil {
		t.Fatalf("NewTokenSetSealer: %v", err)
	}
	return s
}

func TestTokenSetSealerRoundTrips(t *testing.T) {
	s := sealer(t, testClientID, sealKey(1))
	for name, tokens := range map[string]client.TokenSet{
		"every field":        fullTokenSet(),
		"access token alone": {AccessToken: fapi.NewSecret("at-1"), TokenType: "DPoP", Issuer: testIssuer},
	} {
		sealed, err := s.Seal(tokens, "user-1")
		if err != nil {
			t.Fatalf("%s: Seal: %v", name, err)
		}
		for _, secret := range []string{"at-1", "rt-1", "id-token-1", "sam@example.com"} {
			if bytes.Contains(sealed, []byte(secret)) {
				t.Errorf("%s: the sealed set shows %q in the clear", name, secret)
			}
		}
		opened, reseal, err := s.Open(sealed, "user-1")
		if err != nil || reseal {
			t.Fatalf("%s: Open = reseal %v, %v", name, reseal, err)
		}
		if got, want := revealed(opened), revealed(tokens); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: opened = %v\nwant %v", name, got, want)
		}
	}
}

// TestTokenSetSealerRotatesKeys covers a set sealed with an old key:
// it opens while that key is listed, Open asks for it to be sealed
// again, and it doesn't open once the key is dropped.
func TestTokenSetSealerRotatesKeys(t *testing.T) {
	sealed, err := sealer(t, testClientID, sealKey(1)).Seal(fullTokenSet(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	rotated := sealer(t, testClientID, sealKey(2), sealKey(1))
	tokens, reseal, err := rotated.Open(sealed, "user-1")
	if err != nil || !reseal {
		t.Fatalf("Open(after rotation) = reseal %v, %v; want the old key to open it and ask for a reseal", reseal, err)
	}
	resealed, err := rotated.Seal(tokens, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, reseal, err := sealer(t, testClientID, sealKey(2)).Open(resealed, "user-1"); err != nil || reseal {
		t.Errorf("Open(resealed, new key alone) = reseal %v, %v", reseal, err)
	}
	if _, _, err := sealer(t, testClientID, sealKey(2)).Open(sealed, "user-1"); err == nil {
		t.Error("a set sealed with a dropped key still opens")
	}
}

func TestTokenSetSealerRefuses(t *testing.T) {
	s := sealer(t, testClientID, sealKey(1))
	sealed, err := s.Seal(fullTokenSet(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	otherVersion := bytes.Clone(sealed)
	otherVersion[0] = 2
	// Another client of the same issuer, sealing with the same key.
	otherClients, err := sealer(t, "client-2", sealKey(1)).Seal(fullTokenSet(), "user-1")
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		sealed []byte
		owner  string
	}{
		"another owner's":  {sealed, "user-2"},
		"another client's": {otherClients, "user-1"},
		"tampered":         {tampered, "user-1"},
		"other version":    {otherVersion, "user-1"},
		"too short":        {sealed[:4], "user-1"},
		"empty":            {nil, "user-1"},
	} {
		_, _, err := s.Open(tc.sealed, tc.owner)
		var cerr *client.Error
		if !errors.Is(err, client.ErrUnreadableTokenSet) || !errors.As(err, &cerr) {
			t.Errorf("%s: Open = %v, want a *client.Error for ErrUnreadableTokenSet", name, err)
		}
	}
}

func TestTokenSetSealerRefusesMisuse(t *testing.T) {
	c := sealingClient(t, testClientID)
	for name, keys := range map[string][][]byte{
		"no keys":     nil,
		"16-byte key": {sealKey(1)[:16]},
	} {
		if _, err := client.NewTokenSetSealer(c, keys); err == nil {
			t.Errorf("NewTokenSetSealer(%s) = nil error", name)
		}
	}
	if _, err := client.NewTokenSetSealer(nil, [][]byte{sealKey(1)}); err == nil {
		t.Error("NewTokenSetSealer(nil client) = nil error")
	}
	var cerr *client.Error
	if _, err := sealer(t, testClientID, sealKey(1)).Seal(fullTokenSet(), ""); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Errorf("Seal(no owner) = %v, want an invalid_request *client.Error", err)
	}
}

type stoppedClock time.Time

func (c stoppedClock) Now() time.Time { return time.Time(c) }

// TestTokenSetRecordsWhenItWasObtained covers ObtainedAt: the client's
// clock when the token response arrived.
func TestTokenSetRecordsWhenItWasObtained(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c, tokens := refreshClient(t, `{"access_token":"at-2","token_type":"DPoP","expires_in":300}`, func(d *client.Dependencies) { d.Clock = stoppedClock(at) })
	refreshed, err := c.RefreshTokens(t.Context(), client.RefreshTokenRequest{Tokens: tokens})
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	if !refreshed.ObtainedAt.Equal(at) {
		t.Errorf("ObtainedAt = %v, want %v", refreshed.ObtainedAt, at)
	}
}

// TestTokenSetSealerKnowsEveryField fails when TokenSet or IDTokenClaims
// gains a field: add it to sealedTokenSet (token_set_seal.go), to
// fullTokenSet and revealed, then update the counts here. (Issuer isn't
// in sealedTokenSet: the sealer's additional data binds it, and Open
// restores it.)
func TestTokenSetSealerKnowsEveryField(t *testing.T) {
	for typ, want := range map[reflect.Type]int{
		reflect.TypeFor[client.TokenSet]():      14,
		reflect.TypeFor[client.IDTokenClaims](): 11,
	} {
		if got := typ.NumField(); got != want {
			t.Errorf("%s has %d fields, sealing knows %d: seal the new one", typ, got, want)
		}
	}
}

// TestTokenSetSealerRefusesUnencodableDetails covers a TokenSet built by
// hand with authorization details that aren't JSON: Seal can't encode it.
func TestTokenSetSealerRefusesUnencodableDetails(t *testing.T) {
	tokens := fullTokenSet()
	tokens.AuthorizationDetails = json.RawMessage(`[{"type":`)
	var cerr *client.Error
	if _, err := sealer(t, testClientID, sealKey(1)).Seal(tokens, "user-1"); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInternal {
		t.Errorf("Seal(malformed authorization details) = %v, want an internal *client.Error", err)
	}
}

// TestTokenSetSealerBindsTheIssuer: Open restores the sealer's issuer
// as Issuer, even for a set that didn't record one, and Seal refuses a
// set from another issuer rather than relabelling it.
func TestTokenSetSealerBindsTheIssuer(t *testing.T) {
	s := sealer(t, testClientID, sealKey(1))
	sealed, err := s.Seal(client.TokenSet{AccessToken: fapi.NewSecret("at-1"), TokenType: "DPoP"}, "user-1")
	if err != nil {
		t.Fatalf("Seal(no issuer): %v", err)
	}
	opened, _, err := s.Open(sealed, "user-1")
	if err != nil || opened.Issuer != testIssuer {
		t.Fatalf("Open = Issuer %q, %v; want %q", opened.Issuer, err, testIssuer)
	}
	for name, mutate := range map[string]func(*client.TokenSet){
		"another Issuer":       func(t *client.TokenSet) { t.Issuer = "https://other.example.com" },
		"another ID token iss": func(t *client.TokenSet) { t.IDTokenClaims.Issuer = "https://other.example.com" },
	} {
		tokens := fullTokenSet()
		mutate(&tokens)
		var cerr *client.Error
		if _, err := s.Seal(tokens, "user-1"); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
			t.Errorf("Seal(%s) = %v, want invalid_request", name, err)
		}
	}
}
