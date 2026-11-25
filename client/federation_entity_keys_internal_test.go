package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/federation"
)

// TestFederationEntityKeysToleratesWhatItCantRead: an Entity
// Configuration that is missing, isn't a compact JWS, or carries a
// payload that isn't a JSON object, and a JWK Set that doesn't parse,
// each contribute no key rather than failing: Resolve has already
// verified what it returned, so these only arise from a ResolvedEntity
// built some other way.
func TestFederationEntityKeysToleratesWhatItCantRead(t *testing.T) {
	jws := func(payload string) string {
		enc := base64.RawURLEncoding.EncodeToString
		return enc([]byte(`{"alg":"ES256"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("sig"))
	}
	for name, resolved := range map[string]federation.ResolvedEntity{
		"no tokens":               {},
		"not a compact JWS":       {Tokens: []string{"not.a.jws.at.all"}},
		"payload not an object":   {Tokens: []string{jws(`[1,2]`)}},
		"no jwks claim":           {Tokens: []string{jws(`{"iss":"https://op.example"}`)}},
		"JWKS that doesn't parse": {JWKS: json.RawMessage(`{"keys":"nope"}`)},
	} {
		if got := federationEntityKeys(resolved); len(got) != 0 {
			t.Errorf("%s: federationEntityKeys = %d keys, want none", name, len(got))
		}
	}
}

// keyWithoutEqual is a public key type with no Equal method.
type keyWithoutEqual struct{}

// TestIsEntityKeyNeedsComparableKeys: a candidate key whose type can't
// be compared (it has no Equal method) is never taken for an entity
// key, and one that can is matched by value.
func TestIsEntityKeyNeedsComparableKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entityKeys := []crypto.PublicKey{&priv.PublicKey}
	if isEntityKey(keyWithoutEqual{}, entityKeys) {
		t.Error("a key without Equal was taken for an entity key")
	}
	same := priv.PublicKey
	if !isEntityKey(&same, entityKeys) {
		t.Error("an equal ECDSA key wasn't matched")
	}
}
