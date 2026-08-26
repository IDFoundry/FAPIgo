package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// fakeUserInfoIssuerKeys resolves a single fixed ECDSA public key for
// keys.UserInfoVerification only — asserting on req.Purpose is what
// would catch VerifyIssuerJWS resolving against the wrong purpose (e.g.
// keys.IDTokenVerification) if that ever regressed.
type fakeUserInfoIssuerKeys struct {
	// pub is the key to resolve. Leaving it nil resolves to zero keys —
	// a genuinely empty key set, distinct from a resolution error.
	pub *ecdsa.PublicKey
	err error
}

func (f fakeUserInfoIssuerKeys) ResolveIssuerKeys(_ context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	if f.err != nil {
		return keys.IssuerKeySet{}, f.err
	}
	if req.Purpose != keys.UserInfoVerification {
		return keys.IssuerKeySet{}, fmt.Errorf("fakeUserInfoIssuerKeys: unexpected purpose %v", req.Purpose)
	}
	if f.pub == nil {
		return keys.IssuerKeySet{}, nil
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{{KeyID: "as-userinfo-kid", Algorithm: fapi.ES256, PublicKey: f.pub}}}, nil
}

func issuerJWSTestClient(t *testing.T, issuerKeys keys.IssuerKeySource) *Client {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL(idTokenTestIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	return &Client{
		cfg: Config{
			Issuer:     issuer,
			ClientID:   fapi.ClientID(idTokenTestClientID),
			Algorithms: Algorithms{UserInfo: fapi.ES256},
			Limits:     Limits{MaxJOSECompactBytes: 16 * 1024},
		},
		deps: Dependencies{IssuerKeys: issuerKeys},
	}
}

func buildTestJWS(t *testing.T, signer *ecdsa.PrivateKey, keyID string, payload []byte) string {
	t.Helper()
	compact, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, KeyID: keyID}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

func TestVerifyIssuerJWSReturnsVerifiedPayload(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	payload := []byte(`{"sub":"end-user-1","person_info":{"name":"Ada"}}`)
	compact := buildTestJWS(t, signingKey, "as-userinfo-kid", payload)

	c := issuerJWSTestClient(t, fakeUserInfoIssuerKeys{pub: &signingKey.PublicKey})
	got, err := c.VerifyIssuerJWS(context.Background(), compact)
	if err != nil {
		t.Fatalf("VerifyIssuerJWS: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("VerifyIssuerJWS payload = %s, want %s", got, payload)
	}
}

func TestVerifyIssuerJWSRejectsMalformedJWS(t *testing.T) {
	c := issuerJWSTestClient(t, fakeUserInfoIssuerKeys{})
	if _, err := c.VerifyIssuerJWS(context.Background(), "not-a-jws"); err == nil {
		t.Fatalf("VerifyIssuerJWS(malformed) = nil error, want error")
	}
}

func TestVerifyIssuerJWSRejectsIssuerKeyResolutionError(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	compact := buildTestJWS(t, signingKey, "as-userinfo-kid", []byte(`{}`))

	c := issuerJWSTestClient(t, fakeUserInfoIssuerKeys{err: fmt.Errorf("resolve failed")})
	if _, err := c.VerifyIssuerJWS(context.Background(), compact); err == nil {
		t.Fatalf("VerifyIssuerJWS(resolution error) = nil error, want error")
	}
}

func TestVerifyIssuerJWSRejectsNoMatchingIssuerKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	compact := buildTestJWS(t, signingKey, "as-userinfo-kid", []byte(`{}`))

	c := issuerJWSTestClient(t, fakeUserInfoIssuerKeys{})
	if _, err := c.VerifyIssuerJWS(context.Background(), compact); err == nil {
		t.Fatalf("VerifyIssuerJWS(no matching key) = nil error, want error")
	}
}

func TestVerifyIssuerJWSRejectsSignatureVerificationFailure(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	compact := buildTestJWS(t, signingKey, "as-userinfo-kid", []byte(`{}`))

	c := issuerJWSTestClient(t, fakeUserInfoIssuerKeys{pub: &wrongKey.PublicKey})
	if _, err := c.VerifyIssuerJWS(context.Background(), compact); err == nil {
		t.Fatalf("VerifyIssuerJWS(wrong key) = nil error, want error")
	}
}

// TestVerifyIssuerJWSTriesEveryCandidateKey confirms VerifyIssuerJWS
// tries every candidate the issuer advertises rather than only the
// first — the same multi-candidate tolerance validateSignedIDToken
// applies during key rotation.
func TestVerifyIssuerJWSTriesEveryCandidateKey(t *testing.T) {
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	payload := []byte(`{"sub":"end-user-1"}`)
	compact := buildTestJWS(t, signingKey, "as-userinfo-kid", payload)

	multi := multiKeyIssuerKeys{keys: []keys.IssuerKey{
		{KeyID: "wrong-kid", Algorithm: fapi.ES256, PublicKey: &wrongKey.PublicKey},
		{KeyID: "as-userinfo-kid", Algorithm: fapi.ES256, PublicKey: &signingKey.PublicKey},
	}}
	c := issuerJWSTestClient(t, multi)
	got, err := c.VerifyIssuerJWS(context.Background(), compact)
	if err != nil {
		t.Fatalf("VerifyIssuerJWS: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("VerifyIssuerJWS payload = %s, want %s", got, payload)
	}
}

type multiKeyIssuerKeys struct{ keys []keys.IssuerKey }

func (m multiKeyIssuerKeys) ResolveIssuerKeys(_ context.Context, _ keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{Keys: m.keys}, nil
}
