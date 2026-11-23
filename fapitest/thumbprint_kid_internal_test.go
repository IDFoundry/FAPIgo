package fapitest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
)

// recordingClientKeys is a ClientKeySource recording the kid of each
// request it answers.
type recordingClientKeys struct {
	source keys.ClientKeySource

	mu   sync.Mutex
	kids []string
}

func (r *recordingClientKeys) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	r.mu.Lock()
	r.kids = append(r.kids, req.KeyID)
	r.mu.Unlock()
	return r.source.ResolveVerificationKeys(ctx, req)
}

// requested is the kids r has been asked for.
func (r *recordingClientKeys) requested() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.kids)
}

// generateClientKey is a fresh P-256 key.
func generateClientKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// useKidlessClientKeys rebuilds h's client to sign with keys from
// keys.NewKeyManagerFromSigners naming no kid, so each JWT names its
// key's RFC 7638 thumbprint, and h's server to know the client's
// assertion and request object keys through keys.StaticClientKeys
// with no kid either. It returns the derived kids, assertion key first,
// and the source the server now asks.
func useKidlessClientKeys(t *testing.T, h *Harness) ([]string, *recordingClientKeys) {
	t.Helper()
	assertionKey, objectKey := generateClientKey(t), generateClientKey(t)
	km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
		{Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256, Signer: assertionKey},
		{Purpose: keys.RequestObjectSigning, Algorithm: fapi.ES256, Signer: objectKey},
		{Purpose: keys.DPoPProofSigning, Algorithm: fapi.ES256, Signer: generateClientKey(t)},
	})
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	var derived []string
	for _, purpose := range []keys.SigningPurpose{keys.ClientAuthentication, keys.RequestObjectSigning} {
		info, err := km.PublicKey(context.Background(), purpose, fapi.ES256)
		if err != nil || info.KeyID == "" {
			t.Fatalf("PublicKey(%v) = %+v, %v; want a derived kid", purpose, info, err)
		}
		derived = append(derived, info.KeyID)
	}
	clientDeps := h.clientDeps
	clientDeps.Keys = km
	if h.Client, err = client.New(h.clientConfig, clientDeps); err != nil {
		t.Fatalf("client.New: %v", err)
	}

	static, err := keys.NewStaticClientKeys(map[fapi.ClientID]keys.ClientKeyMaterial{ClientID: {VerificationKeys: []keys.VerificationKey{
		{Algorithm: fapi.ES256, PublicKey: &assertionKey.PublicKey},
		{Algorithm: fapi.ES256, PublicKey: &objectKey.PublicKey},
	}}})
	if err != nil {
		t.Fatalf("NewStaticClientKeys: %v", err)
	}
	source := &recordingClientKeys{source: static}
	serverDeps := h.serverDeps
	serverDeps.ClientKeys = source
	if h.authServer.srv, err = server.New(h.serverConfig, serverDeps); err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return derived, source
}

// TestThumbprintKeyIDsEndToEnd: a client built with
// keys.NewKeyManagerFromSigners and no SignerSpec.KeyID completes a flow
// with a server that registered its keys without a kid, under both
// profiles. Each JWT names its key's RFC 7638 thumbprint, which the
// server matches to the key registered without one: the client
// assertions at PAR and the token endpoint and, under Message Signing,
// the request object.
func TestThumbprintKeyIDsEndToEnd(t *testing.T) {
	for name, tc := range map[string]struct {
		profile server.Profile
		// signs is how many of the derived kids, assertion key first,
		// the server is asked for.
		signs int
	}{
		"security":        {server.ProfileFAPISecurity, 1},
		"message signing": {server.ProfileFAPISecurityWithMessageSigning, 2},
	} {
		t.Run(name, func(t *testing.T) {
			h := New(t, Config{Profile: tc.profile})
			derived, source := useKidlessClientKeys(t, h)
			if _, err := h.RunAuthorizationCodeFlow(context.Background(), []string{"openid", "accounts"}); err != nil {
				t.Fatalf("RunAuthorizationCodeFlow: %v", err)
			}
			requested := source.requested()
			for _, kid := range derived[:tc.signs] {
				if !slices.Contains(requested, kid) {
					t.Errorf("the server was asked for kids %q, none of them %q", requested, kid)
				}
			}
		})
	}
}
