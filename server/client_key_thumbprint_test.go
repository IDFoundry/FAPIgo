package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// derivedKeyID is the kid keys.NewKeyManagerFromSigners derives for key
// when its SignerSpec names none: key's RFC 7638 thumbprint.
func derivedKeyID(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{{Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256, Signer: key}})
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	info, err := km.PublicKey(context.Background(), keys.ClientAuthentication, fapi.ES256)
	if err != nil || info.KeyID == "" {
		t.Fatalf("PublicKey = %+v, %v; want a derived kid", info, err)
	}
	return info.KeyID
}

// kidlessJWKS is a JWK Set holding pub with no kid.
func kidlessJWKS(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32)))
	return fmt.Appendf(nil, `{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"alg":"ES256","use":"sig"}]}`, x, y)
}

// kidlessSource builds a ClientKeySource registering own as
// testClientID's key and other as attackerClientID's, neither with a
// kid.
type kidlessSource func(t *testing.T, own, other *ecdsa.PublicKey) keys.ClientKeySource

// kidlessSources are the client key sources this module provides, and
// one returning every key of a client's whatever the kid, which leaves
// the thumbprint match to the server.
func kidlessSources() map[string]kidlessSource {
	return map[string]kidlessSource{
		"StaticClientKeys": func(t *testing.T, own, other *ecdsa.PublicKey) keys.ClientKeySource {
			src, err := keys.NewStaticClientKeys(map[fapi.ClientID]keys.ClientKeyMaterial{
				testClientID:     {VerificationKeys: []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: own}}},
				attackerClientID: {VerificationKeys: []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: other}}},
			})
			if err != nil {
				t.Fatalf("NewStaticClientKeys: %v", err)
			}
			return src
		},
		"ClientJWKSSource": func(t *testing.T, own, other *ecdsa.PublicKey) keys.ClientKeySource {
			docs := map[fapi.ClientID][]byte{testClientID: kidlessJWKS(t, own), attackerClientID: kidlessJWKS(t, other)}
			src, err := keys.NewClientJWKSSource(nil, func(_ context.Context, id fapi.ClientID) (fapi.URL, []byte, error) {
				doc, ok := docs[id]
				if !ok {
					return fapi.URL{}, nil, errors.New("unknown client")
				}
				return fapi.URL{}, doc, nil
			})
			if err != nil {
				t.Fatalf("NewClientJWKSSource: %v", err)
			}
			return src
		},
		"keys/ephemeral": func(t *testing.T, own, other *ecdsa.PublicKey) keys.ClientKeySource {
			src, err := ephemeral.NewClientKeySource(nil, []ephemeral.ClientKeySpec{
				{ClientID: testClientID, JWKS: kidlessJWKS(t, own)},
				{ClientID: attackerClientID, JWKS: kidlessJWKS(t, other)},
			})
			if err != nil {
				t.Fatalf("ephemeral.NewClientKeySource: %v", err)
			}
			return src
		},
		"a source ignoring the kid": func(_ *testing.T, own, other *ecdsa.PublicKey) keys.ClientKeySource {
			return &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
				testClientID:     {{Algorithm: fapi.ES256, PublicKey: own}},
				attackerClientID: {{Algorithm: fapi.ES256, PublicKey: other}},
			}}
		},
	}
}

// signedUse is one kind of JWT a client signs and the server verifies
// with the client's keys: sent, as testClientID's, signed with key and
// naming kid, through the harness its use needs. A JWT naming a kid no
// key of the client's answers to is refused with refused.
type signedUse struct {
	harness func(t *testing.T) harness
	send    func(t *testing.T, h harness, key *ecdsa.PrivateKey, kid string) error
	refused server.ErrorCode
}

// signedUses are the JWTs the server verifies with
// Dependencies.ClientKeys: a client assertion at PAR, the token
// endpoint and revocation, a request object, and a signed CIBA request.
func signedUses() map[string]signedUse {
	return map[string]signedUse{
		"client assertion at PAR": {
			func(t *testing.T) harness { return newHarness(t, server.ProfileFAPISecurity, true) },
			func(t *testing.T, h harness, key *ecdsa.PrivateKey, kid string) error {
				_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
					HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertionAs(t, h, key, testClientID, kid), nil)},
				})
				return err
			},
			server.ErrorInvalidClient,
		},
		"client assertion at the token endpoint": {
			func(t *testing.T) harness {
				return newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
			},
			func(t *testing.T, h harness, key *ecdsa.PrivateKey, kid string) error {
				_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
					HTTP:       server.FormRequest{Parameters: clientCredentialsFormParams(assertionAs(t, h, key, testClientID, kid), "accounts")},
					DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
				})
				return err
			},
			server.ErrorInvalidClient,
		},
		"client assertion at revocation": {
			newRevocationEndpointHarness,
			func(t *testing.T, h harness, key *ecdsa.PrivateKey, kid string) error {
				_, err := h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
					HTTP: server.FormRequest{Parameters: assertionParams(assertionAs(t, h, key, testClientID, kid), formParam("token", "unknown-token"))},
				})
				return err
			},
			server.ErrorInvalidClient,
		},
		"request object": {
			func(t *testing.T) harness { return newHarness(t, server.ProfileFAPISecurityWithMessageSigning, true) },
			sendRequestObject,
			server.ErrorInvalidRequestObject,
		},
		"CIBA request": {
			func(t *testing.T) harness { h, _ := newHarnessWithBackchannel(t); return h },
			sendBackchannelRequest,
			server.ErrorInvalidRequest,
		},
	}
}

// newRevocationEndpointHarness is a harness serving RFC 7009 revocation
// to testClientID, authenticated by client assertion.
func newRevocationEndpointHarness(t *testing.T) harness {
	t.Helper()
	return newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) {
		revocation, err := fapi.ParseEndpointURL(testRevocationEndpoint)
		if err != nil {
			t.Fatal(err)
		}
		c.Endpoints.Revocation = revocation
	}, func(d *server.Dependencies) { d.Revocation = &fakeRevocationSink{} })
}

// signedRequest is a request object for testClientID carrying params,
// signed with key and naming kid.
func signedRequest(t *testing.T, h harness, key *ecdsa.PrivateKey, kid string, params map[string]json.RawMessage) string {
	t.Helper()
	obj, err := requestobject.Create(requestobject.CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: kid,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Parameters: withClientID(t, params),
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}
	return obj
}

// sendRequestObject pushes a request object signed with key and naming
// kid, the client authenticating with an assertion naming no kid.
func sendRequestObject(t *testing.T, h harness, key *ecdsa.PrivateKey, kid string) error {
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", signedRequest(t, h, key, kid, standardAuthParams(t))),
		}},
	})
	return err
}

// sendBackchannelRequest sends a CIBA request signed with key and naming
// kid, the client authenticating with an assertion naming no kid, and
// returns the local error it is answered with, if any.
func sendBackchannelRequest(t *testing.T, h harness, key *ecdsa.PrivateKey, kid string) error {
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), signedRequest(t, h, key, kid, standardBackchannelParams(t)))},
	})
	if local, ok := action.(server.BackchannelAuthenticationLocalError); ok {
		return local.Error
	}
	return err
}

// TestClientKeyWithoutKeyIDMatchesItsThumbprint: a client key registered
// without a kid answers to a JWT naming its RFC 7638 thumbprint, the kid
// keys.NewKeyManagerFromSigners derives for it, wherever the server
// verifies a JWT with the client's keys and whichever source provides
// them. It answers to no other kid, and another client's key never
// stands for it, even when the kid named is that key's own thumbprint.
func TestClientKeyWithoutKeyIDMatchesItsThumbprint(t *testing.T) {
	for useName, use := range signedUses() {
		for sourceName, source := range kidlessSources() {
			t.Run(useName+"/"+sourceName, func(t *testing.T) {
				h := use.harness(t)
				other := generateKey(t)
				deps := h.deps
				deps.ClientKeys = source(t, &h.key.PublicKey, &other.PublicKey)
				srv, err := server.New(h.cfg, deps)
				if err != nil {
					t.Fatalf("server.New: %v", err)
				}
				h.server = srv
				checkThumbprintMatching(t, h, use, other)
			})
		}
	}
}

// checkThumbprintMatching sends use's JWT through h signed with the
// client's own key under its derived kid, which is accepted, then under
// a kid answering to no key, and signed with other, another client's
// key, under other's derived kid, both refused.
func checkThumbprintMatching(t *testing.T, h harness, use signedUse, other *ecdsa.PrivateKey) {
	t.Helper()
	if err := use.send(t, h, h.key, derivedKeyID(t, h.key)); err != nil {
		t.Fatalf("signed with the client's key, naming its derived kid: %v", err)
	}
	for name, sent := range map[string]struct {
		key *ecdsa.PrivateKey
		kid string
	}{
		"an unrelated kid":                         {h.key, "unrelated-kid"},
		"another client's key, by its derived kid": {other, derivedKeyID(t, other)},
	} {
		err := use.send(t, h, sent.key, sent.kid)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if code := serverErrorCode(t, err); code != use.refused {
			t.Fatalf("%s: error code %q, want %q (%v)", name, code, use.refused, err)
		}
	}
}

// TestAttesterKeyWithoutKeyIDDoesNotMatchItsThumbprint: an attester's
// key answers to an attestation's kid only by its KeyID. Unlike a
// client's (TestClientKeyWithoutKeyIDMatchesItsThumbprint), one
// registered without a kid doesn't answer to its thumbprint.
func TestAttesterKeyWithoutKeyIDDoesNotMatchItsThumbprint(t *testing.T) {
	now := time.Now()
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	thumbprint := derivedKeyID(t, attesterKey)
	for name, tc := range map[string]struct {
		registered, named string
		accepted          bool
	}{
		"registered without a kid, none named":           {"", "", true},
		"registered under its thumbprint, it named":      {thumbprint, thumbprint, true},
		"registered without a kid, its thumbprint named": {"", thumbprint, false},
	} {
		t.Run(name, func(t *testing.T) {
			trust := server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{
				testAttesterIssuer: {{KeyID: tc.registered, Algorithm: fapi.ES256, PublicKey: &attesterKey.PublicKey}},
			}}
			h := newAttestationHarness(t, now, nil, trust, nil)
			_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
				ClientAttestations:    []string{createX5CAttestation(t, attesterKey, nil, tc.named, &instanceKey.PublicKey, now)},
				ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", now)},
			})
			if tc.accepted {
				if err != nil {
					t.Fatalf("AuthenticateAttestedClient: %v", err)
				}
				return
			}
			if err == nil || serverErrorCode(t, err) != server.ErrorInvalidClient {
				t.Fatalf("AuthenticateAttestedClient = %v, want invalid_client", err)
			}
		})
	}
}
