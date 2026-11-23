package federation_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// publicJWK is pub as a JWK for alg, named kid unless kid is empty.
func publicJWK(t *testing.T, pub crypto.PublicKey, alg fapi.SignatureAlgorithm, kid string) json.RawMessage {
	t.Helper()
	jwk, err := jose.NewJWK(pub, alg)
	if err != nil {
		t.Fatalf("jose.NewJWK: %v", err)
	}
	if kid != "" {
		jwk = jwk.WithKeyID(kid)
	}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return raw
}

// rpMetadataWithKidlessKey is rpMetadataBuilder's metadata with the
// RP's OIDC key published with no kid, followed by others.
func rpMetadataWithKidlessKey(t *testing.T, others ...json.RawMessage) func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
	return func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"redirect_uris":                   []string{rpID + "/cb"},
			"token_endpoint_auth_method":      "private_key_jwt",
			"token_endpoint_auth_signing_alg": "ES256",
			"jwks":                            map[string]any{"keys": append([]json.RawMessage{publicJWK(t, &rpOIDCKey.PublicKey, fapi.ES256, "")}, others...)},
		})
		if err != nil {
			t.Fatalf("marshal openid_relying_party metadata: %v", err)
		}
		return raw
	}
}

// derivedKeyID is the kid keys.NewKeyManagerFromSigners derives for key,
// signing with alg, when its SignerSpec names none: key's RFC 7638
// thumbprint.
func derivedKeyID(t *testing.T, key crypto.Signer, alg fapi.SignatureAlgorithm) string {
	t.Helper()
	km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{{Purpose: keys.ClientAuthentication, Algorithm: alg, Signer: key}})
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	info, err := km.PublicKey(context.Background(), keys.ClientAuthentication, alg)
	if err != nil || info.KeyID == "" {
		t.Fatalf("PublicKey = %+v, %v; want a derived kid", info, err)
	}
	return info.KeyID
}

// TestAutomaticClientKeySourceMatchesThumbprintOfKeyWithoutKeyID: a key
// an RP publishes with no kid answers to a request naming its RFC 7638
// thumbprint, the kid keys.NewKeyManagerFromSigners derives for it, as
// keys.VerificationKey.KeyID sets out for every client key source,
// whether it is a P-256, an RSA or an Ed25519 key; a key published with
// a kid answers to that kid alone.
func TestAutomaticClientKeySourceMatchesThumbprintOfKeyWithoutKeyID(t *testing.T) {
	named := generateKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := setupAutomaticRegistrationFixture(t, rpMetadataWithKidlessKey(t,
		publicJWK(t, &named.PublicKey, fapi.ES256, "rp-named"),
		publicJWK(t, &rsaKey.PublicKey, fapi.PS256, ""),
		publicJWK(t, edPub, fapi.EdDSA, "")))
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, validAutomaticRegistrationConfig(), fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	src, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, repo)
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}
	for _, tc := range []struct {
		name string
		alg  fapi.SignatureAlgorithm
		kid  string
		want crypto.PublicKey // nil: no key
	}{
		{"the kid-less key's thumbprint", fapi.ES256, derivedKeyID(t, f.rpOIDCKey, fapi.ES256), &f.rpOIDCKey.PublicKey},
		{"the kid-less RSA key's thumbprint", fapi.PS256, derivedKeyID(t, rsaKey, fapi.PS256), &rsaKey.PublicKey},
		{"the kid-less Ed25519 key's thumbprint", fapi.EdDSA, derivedKeyID(t, edKey, fapi.EdDSA), edPub},
		{"the named key's kid", fapi.ES256, "rp-named", &named.PublicKey},
		{"the named key's thumbprint", fapi.ES256, derivedKeyID(t, named, fapi.ES256), nil},
		{"an unrelated kid", fapi.ES256, "unrelated", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
				ClientID: fapi.ClientID(f.rpID), Purpose: keys.ClientAssertionVerification, Algorithm: tc.alg, KeyID: tc.kid,
			})
			if err != nil {
				t.Fatalf("ResolveVerificationKeys: %v", err)
			}
			requireResolvedKey(t, set, tc.want)
		})
	}
}

// requireResolvedKey fails t unless set holds want alone, or no key
// when want is nil.
func requireResolvedKey(t *testing.T, set keys.VerificationKeySet, want crypto.PublicKey) {
	t.Helper()
	if want == nil {
		if len(set.Keys) != 0 {
			t.Fatalf("ResolveVerificationKeys = %d keys, want none", len(set.Keys))
		}
		return
	}
	if len(set.Keys) != 1 || !want.(interface{ Equal(crypto.PublicKey) bool }).Equal(set.Keys[0].PublicKey) {
		t.Fatalf("ResolveVerificationKeys = %+v, want the one key", set.Keys)
	}
}
