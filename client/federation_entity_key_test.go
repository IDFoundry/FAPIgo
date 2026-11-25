package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// listedIssuerKeys resolves every request to pubs, in order, with the
// requested algorithm and kid: an issuer's JWK Set listing them.
type listedIssuerKeys struct{ pubs []crypto.PublicKey }

func (s listedIssuerKeys) ResolveIssuerKeys(_ context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	var set keys.IssuerKeySet
	for _, pub := range s.pubs {
		set.Keys = append(set.Keys, keys.IssuerKey{KeyID: req.KeyID, Algorithm: req.Algorithm, PublicKey: pub})
	}
	return set, nil
}

func (listedIssuerKeys) Capabilities() keys.KeySourceCapabilities {
	return keys.KeySourceCapabilities{LiveFetchHardened: true}
}

// entityKeyTestClient builds a Client from DiscoverViaFederation's
// metadata for an OP whose federation entity key is entityKey (and, when
// extra is set, whose Entity Configuration also publishes extra), with
// Dependencies.IssuerKeys listing protocolKeys.
func entityKeyTestClient(t *testing.T, extra *ecdsa.PublicKey, protocolKeys func(entityKey *ecdsa.PrivateKey) []crypto.PublicKey) (*client.Client, *ecdsa.PrivateKey) {
	t.Helper()
	entityID, resolver, entityKey := selfAnchoredOpenIDProviderKeys(t, func(entityID string) map[string]json.RawMessage {
		return map[string]json.RawMessage{"openid_provider": mustMarshal(t, map[string]any{
			"issuer":                                entityID,
			"authorization_endpoint":                entityID + "/authorize",
			"pushed_authorization_request_endpoint": entityID + "/par",
			"token_endpoint":                        entityID + "/token",
			"jwks_uri":                              entityID + "/jwks",
			"userinfo_endpoint":                     entityID + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"userinfo_signing_alg_values_supported": []string{"ES256"},
			"client_registration_types_supported":   []string{"automatic"},
		})}
	}, extra)
	discovered, err := client.DiscoverViaFederation(context.Background(), resolver, entityID)
	if err != nil {
		t.Fatalf("DiscoverViaFederation: %v", err)
	}
	cfg := validConfig(t)
	cfg.Issuer = discovered.Issuer()
	cfg.Endpoints = client.Endpoints{}
	cfg.Algorithms.IDToken = fapi.ES256
	cfg.Algorithms.UserInfo = fapi.ES256
	deps := validDependencies(t)
	deps.IssuerKeys = listedIssuerKeys{pubs: protocolKeys(entityKey)}
	c, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		t.Fatalf("NewFromDiscovery: %v", err)
	}
	return c, entityKey
}

func generateEntityTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signIssuerJWS(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	signed, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, KeyID: "as-kid"}, []byte(`{"sub":"user"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return signed
}

// wantEntityKeyRefused checks err is the ErrorInvalidResponse a JWS
// only an entity key matches gets.
func wantEntityKeyRefused(t *testing.T, err error) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse || !strings.Contains(err.Error(), "federation entity keys") {
		t.Fatalf("VerifyIssuerJWS = %v, want ErrorInvalidResponse refusing the federation entity key", err)
	}
}

// TestClientRefusesFederationEntityKeyAsProtocolKey: a Client built
// from DiscoverViaFederation's metadata doesn't accept the OP's
// federation entity key as a protocol key, even when the OP lists it
// among the keys it signs protocol messages with. Listed alone, a JWS
// it signed is refused as signed with an entity key; listed beside a
// distinct protocol key, that JWS still doesn't verify, while one the
// protocol key signed does.
func TestClientRefusesFederationEntityKeyAsProtocolKey(t *testing.T) {
	alone, entityKey := entityKeyTestClient(t, nil, func(entityKey *ecdsa.PrivateKey) []crypto.PublicKey {
		return []crypto.PublicKey{&entityKey.PublicKey}
	})
	_, err := alone.VerifyIssuerJWS(context.Background(), signIssuerJWS(t, entityKey))
	wantEntityKeyRefused(t, err)

	protocolKey := generateEntityTestKey(t)
	both, entityKey := entityKeyTestClient(t, nil, func(entityKey *ecdsa.PrivateKey) []crypto.PublicKey {
		return []crypto.PublicKey{&entityKey.PublicKey, &protocolKey.PublicKey}
	})
	_, err = both.VerifyIssuerJWS(context.Background(), signIssuerJWS(t, entityKey))
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse || !errors.Is(err, jose.ErrInvalidSignature) {
		t.Fatalf("VerifyIssuerJWS(signed with the entity key, protocol key listed too) = %v, want ErrorInvalidResponse for an invalid signature", err)
	}
	if _, err := both.VerifyIssuerJWS(context.Background(), signIssuerJWS(t, protocolKey)); err != nil {
		t.Fatalf("VerifyIssuerJWS(signed with the protocol key) = %v, want it verified", err)
	}
}

// TestClientRefusesEntityConfigurationKeyAsProtocolKey: a key the OP's
// own Entity Configuration publishes as a federation entity key is
// refused as a protocol key too, though the Trust Anchor's JWK Set for
// the OP doesn't list it.
func TestClientRefusesEntityConfigurationKeyAsProtocolKey(t *testing.T) {
	second := generateEntityTestKey(t)
	c, _ := entityKeyTestClient(t, &second.PublicKey, func(*ecdsa.PrivateKey) []crypto.PublicKey {
		return []crypto.PublicKey{&second.PublicKey}
	})
	_, err := c.VerifyIssuerJWS(context.Background(), signIssuerJWS(t, second))
	wantEntityKeyRefused(t, err)
}
