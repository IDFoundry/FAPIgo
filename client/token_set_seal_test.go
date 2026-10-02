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

func sealKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

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
	}
}

// revealed is t with its secrets readable, for comparing token sets.
func revealed(t client.TokenSet) map[string]any {
	return map[string]any{
		"access": t.AccessToken.Reveal(), "type": t.TokenType, "scope": t.Scope, "details": string(t.AuthorizationDetails),
		"expiresIn": t.ExpiresIn, "hasExpiresIn": t.HasExpiresIn, "obtainedAt": t.ObtainedAt.UTC(),
		"id": t.IDToken.Reveal(), "hasID": t.HasIDToken, "sub": t.Subject, "claims": claimsWithUTC(t.IDTokenClaims),
		"refresh": t.RefreshToken.Reveal(), "hasRefresh": t.HasRefreshToken,
	}
}

func claimsWithUTC(c client.IDTokenClaims) client.IDTokenClaims {
	c.AuthTime, c.ExpiresAt, c.IssuedAt = c.AuthTime.UTC(), c.ExpiresAt.UTC(), c.IssuedAt.UTC()
	return c
}

func TestSealTokenSetRoundTrips(t *testing.T) {
	c := sealingClient(t, testClientID)
	for name, tokens := range map[string]client.TokenSet{
		"every field":        fullTokenSet(),
		"access token alone": {AccessToken: fapi.NewSecret("at-1"), TokenType: "DPoP"},
	} {
		sealed, err := c.SealTokenSet(tokens, sealKey(1))
		if err != nil {
			t.Fatalf("%s: SealTokenSet: %v", name, err)
		}
		for _, secret := range []string{"at-1", "rt-1", "id-token-1", "sam@example.com"} {
			if bytes.Contains(sealed, []byte(secret)) {
				t.Errorf("%s: the sealed set shows %q in the clear", name, secret)
			}
		}
		opened, err := c.OpenTokenSet(sealed, sealKey(1))
		if err != nil {
			t.Fatalf("%s: OpenTokenSet: %v", name, err)
		}
		if got, want := revealed(opened), revealed(tokens); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: opened = %v\nwant %v", name, got, want)
		}
	}
}

// TestOpenTokenSetRotatesKeys covers a set sealed with an old key
// opening while that key is still listed, and not once it's dropped.
func TestOpenTokenSetRotatesKeys(t *testing.T) {
	c := sealingClient(t, testClientID)
	sealed, err := c.SealTokenSet(fullTokenSet(), sealKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.OpenTokenSet(sealed, sealKey(2), sealKey(1)); err != nil {
		t.Errorf("OpenTokenSet(new, old) = %v, want the old key to open it", err)
	}
	if _, err := c.OpenTokenSet(sealed, sealKey(2)); err == nil {
		t.Error("OpenTokenSet(new) opened a set sealed with a dropped key")
	}
}

func TestOpenTokenSetRefuses(t *testing.T) {
	c := sealingClient(t, testClientID)
	sealed, err := c.SealTokenSet(fullTokenSet(), sealKey(1))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	otherVersion := bytes.Clone(sealed)
	otherVersion[0] = 2

	// Another client of the same issuer, sealing with the same key.
	otherSealed, err := sealingClient(t, "client-2").SealTokenSet(fullTokenSet(), sealKey(1))
	if err != nil {
		t.Fatal(err)
	}

	for name, b := range map[string][]byte{
		"another client's": otherSealed,
		"tampered":         tampered,
		"other version":    otherVersion,
		"too short":        sealed[:4],
		"empty":            nil,
	} {
		if _, err := c.OpenTokenSet(b, sealKey(1)); err == nil {
			t.Errorf("%s: OpenTokenSet = nil error, want refusal", name)
		}
	}
}

func TestSealTokenSetRefusesABadKey(t *testing.T) {
	c := sealingClient(t, testClientID)
	if _, err := c.SealTokenSet(fullTokenSet(), sealKey(1)[:16]); err == nil {
		t.Error("SealTokenSet(16-byte key) = nil error")
	}
	sealed, err := c.SealTokenSet(fullTokenSet(), sealKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.OpenTokenSet(sealed, sealKey(1)[:16]); err == nil {
		t.Error("OpenTokenSet(16-byte key) = nil error")
	}
	var cerr *client.Error
	if _, err := c.OpenTokenSet(nil, sealKey(1)); !errors.As(err, &cerr) {
		t.Errorf("OpenTokenSet(nil) = %v, want a *client.Error", err)
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
