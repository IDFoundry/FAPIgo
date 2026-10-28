package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// kidIndexClientKeys is the mistake keys.TestClientKeySourceContract
// exists to catch: a ClientKeySource that indexes every client's keys
// by kid alone, ignoring the client ID it is asked about, so a client
// signing with its own key and kid is verified as whichever client it
// names.
type kidIndexClientKeys struct {
	byKID map[string]keys.VerificationKey
}

func (k kidIndexClientKeys) ResolveVerificationKeys(_ context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	if v, ok := k.byKID[req.KeyID]; ok && v.Algorithm == req.Algorithm {
		return keys.VerificationKeySet{Keys: []keys.VerificationKey{v}}, nil
	}
	return keys.VerificationKeySet{}, errors.New("unknown kid")
}

func (kidIndexClientKeys) Capabilities() keys.KeySourceCapabilities {
	return keys.KeySourceCapabilities{LiveFetchHardened: true}
}

// attackerClientID is a second registered client, signing with its own
// key, that tries to authenticate as testClientID.
const attackerClientID fapi.ClientID = "attacker-client"

// assertionAs signs a client assertion naming clientID with key and kid.
func assertionAs(t *testing.T, h harness, key *ecdsa.PrivateKey, clientID fapi.ClientID, kid string) string {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: key, Algorithm: fapi.ES256, KeyID: kid,
		ClientID: clientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}

// clientKeySourceCase is a harness whose server resolves client keys
// through source, where testClientID publishes h.key under victimKID and
// attackerClientID publishes attacker under attackerKID.
type clientKeySourceCase struct {
	name                     string
	victimKID, attackerKID   string
	source                   func(t *testing.T, victim, attacker *ecdsa.PrivateKey, victimKID, attackerKID string) keys.ClientKeySource
	wantAttackerAuthenticate bool
}

func staticClientKeysFor(t *testing.T, victim, attacker *ecdsa.PrivateKey, victimKID, attackerKID string) keys.ClientKeySource {
	t.Helper()
	src, err := keys.NewStaticClientKeys(map[fapi.ClientID]keys.ClientKeyMaterial{
		testClientID:     {VerificationKeys: []keys.VerificationKey{{KeyID: victimKID, Algorithm: fapi.ES256, PublicKey: &victim.PublicKey}}},
		attackerClientID: {VerificationKeys: []keys.VerificationKey{{KeyID: attackerKID, Algorithm: fapi.ES256, PublicKey: &attacker.PublicKey}}},
	})
	if err != nil {
		t.Fatalf("NewStaticClientKeys: %v", err)
	}
	return src
}

func clientJWKSSourceFor(t *testing.T, victim, attacker *ecdsa.PrivateKey, victimKID, attackerKID string) keys.ClientKeySource {
	t.Helper()
	docs := map[fapi.ClientID][]byte{
		testClientID:     ecJWKS(t, &victim.PublicKey, victimKID),
		attackerClientID: ecJWKS(t, &attacker.PublicKey, attackerKID),
	}
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
}

func kidIndexFor(_ *testing.T, victim, attacker *ecdsa.PrivateKey, victimKID, attackerKID string) keys.ClientKeySource {
	return kidIndexClientKeys{byKID: map[string]keys.VerificationKey{
		victimKID:   {KeyID: victimKID, Algorithm: fapi.ES256, PublicKey: &victim.PublicKey},
		attackerKID: {KeyID: attackerKID, Algorithm: fapi.ES256, PublicKey: &attacker.PublicKey},
	}}
}

// ecJWKS is a JWK Set holding pub under kid.
func ecJWKS(t *testing.T, pub *ecdsa.PublicKey, kid string) []byte {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32)))
	return fmt.Appendf(nil, `{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q,"alg":"ES256","use":"sig"}]}`, x, y, kid)
}

// TestClientAssertionWithAnotherClientsKeyIsRefused: a registered
// client signing a client assertion that names another client, with
// its own key and kid, is refused with both bundled production client
// key sources — including when both clients publish the same kid. The
// kid-indexed source, which ignores the client ID, lets it through:
// the server accepts whichever key the source returns, which is why
// keys.TestClientKeySourceContract checks per-client isolation.
func TestClientAssertionWithAnotherClientsKeyIsRefused(t *testing.T) {
	cases := []clientKeySourceCase{
		{name: "StaticClientKeys", victimKID: "victim", attackerKID: "attacker", source: staticClientKeysFor},
		{name: "StaticClientKeys/shared kid", victimKID: "k1", attackerKID: "k1", source: staticClientKeysFor},
		{name: "ClientJWKSSource", victimKID: "victim", attackerKID: "attacker", source: clientJWKSSourceFor},
		{name: "ClientJWKSSource/shared kid", victimKID: "k1", attackerKID: "k1", source: clientJWKSSourceFor},
		{name: "kid-indexed source (the mistake)", victimKID: "victim", attackerKID: "attacker", source: kidIndexFor, wantAttackerAuthenticate: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runClientKeySourceCase(t, c) })
	}
}

func runClientKeySourceCase(t *testing.T, c clientKeySourceCase) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	attacker := generateKey(t)
	deps := h.deps
	deps.ClientKeys = c.source(t, h.key, attacker, c.victimKID, c.attackerKID)
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	request := func(assertion string) error {
		_, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
			HTTP:       server.FormRequest{Parameters: clientCredentialsFormParams(assertion, "accounts")},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}

	if err := request(assertionAs(t, h, h.key, testClientID, c.victimKID)); err != nil {
		t.Fatalf("the client's own assertion: %v", err)
	}
	err = request(assertionAs(t, h, attacker, testClientID, c.attackerKID))
	if c.wantAttackerAuthenticate {
		if err != nil {
			t.Fatalf("kid-indexed source refused the attacker (%v); this case shows the mistake the contract catches", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("an assertion naming %q, signed with %q's key (kid %q), authenticated", testClientID, attackerClientID, c.attackerKID)
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

// contractChildEnv makes this test binary run the contract against the
// kid-indexed source in a child process, so the parent can check it
// fails without failing itself.
const contractChildEnv = "FAPIGO_TEST_KID_INDEX_CONTRACT_CHILD"

// TestClientKeySourceContractRejectsKidIndexedSource: the kid-indexed
// source, which lets one client authenticate as another (see
// TestClientAssertionWithAnotherClientsKeyIsRefused), fails
// keys.TestClientKeySourceContract on per-client isolation.
func TestClientKeySourceContractRejectsKidIndexedSource(t *testing.T) {
	if os.Getenv(contractChildEnv) == "1" {
		keys.TestClientKeySourceContract(t, newKidIndexFromJWKS)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestClientKeySourceContractRejectsKidIndexedSource$", "-test.v")
	cmd.Env = append(os.Environ(), contractChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the contract passed against a kid-indexed source (err %v):\n%s", err, out)
	}
	for _, failed := range []string{"KeyIDNeverResolvesForAnotherClient", "SharedKeyIDResolvesPerClient", "UnknownClientIsAnError"} {
		if !strings.Contains(string(out), "--- FAIL: TestClientKeySourceContractRejectsKidIndexedSource/"+failed) {
			t.Errorf("the contract's %s check didn't fail against a kid-indexed source:\n%s", failed, out)
		}
	}
}

// newKidIndexFromJWKS builds the kid-indexed source over the contract's
// clients, as a JWKS cache keyed by kid would: a later client's key
// overwrites an earlier one under a shared kid.
func newKidIndexFromJWKS(t *testing.T, clients map[fapi.ClientID][]byte) keys.ClientKeySource {
	t.Helper()
	idx := kidIndexClientKeys{byKID: map[string]keys.VerificationKey{}}
	for id, doc := range clients {
		static, err := keys.NewStaticClientKeys(map[fapi.ClientID]keys.ClientKeyMaterial{id: {JWKS: doc}})
		if err != nil {
			t.Fatalf("NewStaticClientKeys: %v", err)
		}
		for _, alg := range []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256} {
			set, err := static.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: id, Algorithm: alg})
			if err != nil {
				t.Fatalf("ResolveVerificationKeys: %v", err)
			}
			for _, k := range set.Keys {
				idx.byKID[k.KeyID] = k
			}
		}
	}
	return idx
}
