package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// nilKeyPublisher declares that it signs no access tokens.
type nilKeyPublisher struct{ JWTAccessTokens }

func (nilKeyPublisher) AccessTokenSigningKeys() (keys.KeyManager, fapi.SignatureAlgorithm) {
	return nil, 0
}

// TestAccessTokenSigningKeys: the keys an issuer signs with come from
// JWTAccessTokens itself, by value or pointer, or an
// AccessTokenKeyPublisher's declaration, never from an embedded
// JWTAccessTokens alone.
func TestAccessTokenSigningKeys(t *testing.T) {
	manager := mustKeyManager(t, keys.AccessTokenSigning)
	jwt := JWTAccessTokens{Keys: manager, Algorithm: fapi.ES256}
	for name, tc := range map[string]struct {
		issuer AccessTokenIssuer
		want   bool
	}{
		"value":                {jwt, true},
		"pointer":              {&jwt, true},
		"nil pointer":          {(*JWTAccessTokens)(nil), false},
		"opaque":               {OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}, false},
		"embedded, undeclared": {struct{ JWTAccessTokens }{jwt}, false},
		"publisher of no keys": {nilKeyPublisher{jwt}, false},
		"nil interface":        {nil, false},
	} {
		use, ok := accessTokenSigningKeys(tc.issuer)
		if ok != tc.want || (ok && (use.Manager != manager || use.Purpose != keys.AccessTokenSigning || use.Algorithm != fapi.ES256)) {
			t.Errorf("%s: accessTokenSigningKeys = %+v, %v, want ok %v", name, use, ok, tc.want)
		}
	}
	if err := checkEmbeddedJWTAccessTokens(nilKeyPublisher{jwt}); err != nil {
		t.Errorf("checkEmbeddedJWTAccessTokens(publisher) = %v", err)
	}
	if err := checkEmbeddedJWTAccessTokens(OpaqueAccessTokens{}); err != nil {
		t.Errorf("checkEmbeddedJWTAccessTokens(opaque) = %v", err)
	}
	if attesterTrustSources(nil) != nil {
		t.Error("attesterTrustSources(nil) != nil")
	}
	if err := (NoBackchannelNotifications{}).Notify(context.Background(), BackchannelNotification{}); err != nil {
		t.Errorf("NoBackchannelNotifications.Notify = %v", err)
	}
}

// TestIsOwnJWTAccessToken: RevokeToken recognises a JWT access token
// signed with any key the issuer currently publishes (all of a
// keys.RotatingKeyManager's), and nothing when the issuer signs no
// tokens or its keys can't be read.
func TestIsOwnJWTAccessToken(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	manager := mustKeyManager(t, keys.AccessTokenSigning)
	jwt := JWTAccessTokens{Keys: manager, Algorithm: fapi.ES256}
	now := time.Now()
	raw, _, err := jwt.IssueAccessToken(context.Background(), AccessTokenParams{
		Issuer: issuer.String(), Subject: "user-1", Audience: issuer.String(), ClientID: "client-1",
		SenderConstrain: storage.SenderConstrainDPoP, Thumbprint: "jkt",
		Now: now, Lifetime: time.Minute, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	serverWith := func(issuerDep AccessTokenIssuer) *Server {
		return &Server{
			cfg:  Config{Issuer: issuer, Limits: Limits{MaxClockSkew: time.Second}},
			deps: Dependencies{AccessTokens: issuerDep, Clock: SystemClock{}},
		}
	}
	if !serverWith(jwt).isOwnJWTAccessToken(context.Background(), "client-1", raw) {
		t.Error("rotating key manager: isOwnJWTAccessToken = false, want true")
	}
	if serverWith(OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}).isOwnJWTAccessToken(context.Background(), "client-1", raw) {
		t.Error("opaque issuer: isOwnJWTAccessToken = true, want false")
	}
	unreadable := JWTAccessTokens{Keys: mustKeyManager(t, keys.IDTokenSigning), Algorithm: fapi.ES256}
	if serverWith(unreadable).isOwnJWTAccessToken(context.Background(), "client-1", raw) {
		t.Error("keys without an access token key: isOwnJWTAccessToken = true, want false")
	}
}

// mustKeyManager is a keys.RotatingKeyManager holding one ES256 key for
// purpose.
func mustKeyManager(t *testing.T, purpose keys.SigningPurpose) keys.KeyManager {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{{Purpose: purpose, Algorithm: fapi.ES256, Signer: key, KeyID: "k-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.(keys.RotatingKeyManager); !ok {
		t.Fatalf("%T isn't a keys.RotatingKeyManager", manager)
	}
	return manager
}
