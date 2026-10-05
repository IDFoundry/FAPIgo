package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

func TestStaticAttesterKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const attester = "https://attester.example.com"
	source := keys.StaticAttesterKeys{attester: {{KeyID: "a1", Algorithm: fapi.ES256, PublicKey: &key.PublicKey}}}

	set, err := source.ResolveAttesterKeys(context.Background(), keys.AttesterKeyRequest{Issuer: attester, Algorithm: fapi.ES256})
	if err != nil {
		t.Fatalf("ResolveAttesterKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "a1" {
		t.Fatalf("keys = %+v, want the registered key", set.Keys)
	}
	set.Keys[0].KeyID = "changed"
	if source[attester][0].KeyID != "a1" {
		t.Fatal("ResolveAttesterKeys returned the registered slice itself")
	}

	if _, err := source.ResolveAttesterKeys(context.Background(), keys.AttesterKeyRequest{Issuer: "https://other.example.com"}); err == nil {
		t.Fatal("ResolveAttesterKeys for an unknown attester succeeded")
	}
	if !source.Capabilities().LiveFetchHardened {
		t.Fatal("StaticAttesterKeys must declare LiveFetchHardened")
	}
}
