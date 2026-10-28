package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// This file is a reusable contract test suite, not a _test.go file,
// so an application's own ClientKeySource can import it and run it
// against its own factory, as storage's Test*Contract functions are
// for stores.

// Client IDs the contract registers.
const (
	contractClientA       fapi.ClientID = "contract-client-a"
	contractClientB       fapi.ClientID = "contract-client-b"
	contractUnknownClient fapi.ClientID = "contract-client-unregistered"
)

// Key IDs the contract's clients publish. contractSharedKID is
// published by both clients, each for its own key.
const (
	contractKIDAES256 = "a-es256"
	contractKIDAPS256 = "a-ps256"
	contractKIDBES256 = "b-es256"
	contractSharedKID = "shared"
)

// contractKey is one key a contract client publishes.
type contractKey struct {
	kid string
	alg fapi.SignatureAlgorithm
	pub crypto.PublicKey
}

// contractFixture is the contract's registered clients and their keys.
type contractFixture struct {
	keys map[fapi.ClientID][]contractKey
}

// TestClientKeySourceContract checks a ClientKeySource keeps each
// client's keys to that client, which the server relies on when it
// verifies a client assertion or signed request: it accepts whichever
// key the source returns for the client ID the token names, so a source
// that answers with another client's key lets one client authenticate
// as the other.
//
// newSource must return a source serving exactly clients' keys — each
// client ID mapped to that client's JWK Set document, as it would be
// registered (inline, or published at the client's jwks_uri). The
// contract checks that:
//
//   - a kid one client publishes never resolves for another client;
//   - a kid two clients both publish resolves to each client's own key;
//   - a client ID that isn't registered is an error, never a fallback
//     set, with or without a kid;
//   - only keys for the requested algorithm are returned;
//   - every key returned belongs to the requesting client (and has the
//     requested kid, when one is requested);
//   - a client's own key resolves by its kid, and without one.
//
// It checks behaviour through ResolveVerificationKeys only, so it
// can't tell a source that is correct by design from one that only
// passes these cases; it is a check against the common mistakes (a
// kid-indexed cache shared across clients, a default key set for an
// unknown client), not a proof.
func TestClientKeySourceContract(t *testing.T, newSource func(t *testing.T, clients map[fapi.ClientID][]byte) ClientKeySource) {
	t.Helper()
	fixture := newContractFixture(t)
	documents := fixture.documents(t)
	source := func(t *testing.T) ClientKeySource {
		t.Helper()
		s := newSource(t, documents)
		if s == nil {
			t.Fatalf("newSource returned nil")
		}
		return s
	}

	for _, c := range contractChecks {
		t.Run(c.name, func(t *testing.T) {
			for _, problem := range c.check(source(t), fixture) {
				t.Error(problem)
			}
		})
	}
}

// contractCheck is one of TestClientKeySourceContract's subtests: check
// returns what it found wrong with a source, nothing if it passes.
type contractCheck struct {
	name  string
	check func(ClientKeySource, contractFixture) []string
}

// contractChecks are TestClientKeySourceContract's subtests, in order.
var contractChecks = []contractCheck{
	{"KeyIDNeverResolvesForAnotherClient", checkContractKeyIDNeverResolvesForAnotherClient},
	{"SharedKeyIDResolvesPerClient", checkContractSharedKeyIDResolvesPerClient},
	{"UnknownClientIsAnError", checkContractUnknownClientIsAnError},
	{"FiltersByAlgorithm", checkContractFiltersByAlgorithm},
	{"EveryKeyBelongsToTheRequestingClient", checkContractEveryKeyBelongsToTheRequestingClient},
	{"ResolvesOwnKey", checkContractResolvesOwnKey},
}

// newContractFixture generates the contract clients' keys: client A
// publishes an ES256 and a PS256 key plus an ES256 key under the shared
// kid; client B an ES256 key plus its own, different ES256 key under the
// shared kid.
func newContractFixture(t *testing.T) contractFixture {
	t.Helper()
	ec := func() crypto.PublicKey {
		t.Helper()
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("contract: generate P-256 key: %v", err)
		}
		return &k.PublicKey
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("contract: generate RSA key: %v", err)
	}
	return contractFixture{keys: map[fapi.ClientID][]contractKey{
		contractClientA: {
			{kid: contractKIDAES256, alg: fapi.ES256, pub: ec()},
			{kid: contractKIDAPS256, alg: fapi.PS256, pub: &rsaKey.PublicKey},
			{kid: contractSharedKID, alg: fapi.ES256, pub: ec()},
		},
		contractClientB: {
			{kid: contractKIDBES256, alg: fapi.ES256, pub: ec()},
			{kid: contractSharedKID, alg: fapi.ES256, pub: ec()},
		},
	}}
}

// documents is each client's JWK Set document.
func (f contractFixture) documents(t *testing.T) map[fapi.ClientID][]byte {
	t.Helper()
	out := make(map[fapi.ClientID][]byte, len(f.keys))
	for id, ks := range f.keys {
		var set struct {
			Keys []jose.JWK `json:"keys"`
		}
		for _, k := range ks {
			jwk, err := jose.NewJWK(k.pub, k.alg)
			if err != nil {
				t.Fatalf("contract: %v", err)
			}
			set.Keys = append(set.Keys, jwk.WithKeyID(k.kid))
		}
		body, err := json.Marshal(set)
		if err != nil {
			t.Fatalf("contract: marshal jwks: %v", err)
		}
		out[id] = body
	}
	return out
}

// key is client id's fixture key with kid.
func (f contractFixture) key(id fapi.ClientID, kid string) contractKey {
	for _, k := range f.keys[id] {
		if k.kid == kid {
			return k
		}
	}
	return contractKey{}
}

// owns reports whether pub is one of client id's keys.
func (f contractFixture) owns(id fapi.ClientID, pub crypto.PublicKey) bool {
	return containsPublicKey(f.keys[id], func(k contractKey) crypto.PublicKey { return k.pub }, pub)
}

func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// containsPublicKey reports whether any of ks has public key pub.
func containsPublicKey[K any](ks []K, pubOf func(K) crypto.PublicKey, pub crypto.PublicKey) bool {
	for _, k := range ks {
		if samePublicKey(pubOf(k), pub) {
			return true
		}
	}
	return false
}

func verificationKeyPublic(k VerificationKey) crypto.PublicKey { return k.PublicKey }

// contractResolve asks source for req and returns the keys, treating an
// error as no keys (allowed wherever the contract only requires that no
// wrong key is returned).
func contractResolve(source ClientKeySource, req ClientKeyRequest) []VerificationKey {
	set, err := source.ResolveVerificationKeys(context.Background(), req)
	if err != nil {
		return nil
	}
	return set.Keys
}

// checkContractKeyIDNeverResolvesForAnotherClient: a request naming
// client B with a kid only client A publishes (as an assertion from A
// claiming to be B would) gets none of A's keys, and vice versa.
func checkContractKeyIDNeverResolvesForAnotherClient(source ClientKeySource, f contractFixture) []string {
	cases := []struct {
		requester, owner fapi.ClientID
		kid              string
		alg              fapi.SignatureAlgorithm
	}{
		{contractClientB, contractClientA, contractKIDAES256, fapi.ES256},
		{contractClientB, contractClientA, contractKIDAPS256, fapi.PS256},
		{contractClientA, contractClientB, contractKIDBES256, fapi.ES256},
	}
	var problems []string
	for _, c := range cases {
		got := contractResolve(source, ClientKeyRequest{ClientID: c.requester, Purpose: ClientAssertionVerification, Algorithm: c.alg, KeyID: c.kid})
		for _, k := range got {
			if f.owns(c.owner, k.PublicKey) {
				problems = append(problems, fmt.Sprintf("kid %q of client %q resolved for client %q: a client could authenticate as another", c.kid, c.owner, c.requester))
			}
		}
		if len(got) > 0 {
			problems = append(problems, fmt.Sprintf("kid %q, which client %q doesn't publish, resolved %d key(s) for it", c.kid, c.requester, len(got)))
		}
	}
	return problems
}

// checkContractSharedKeyIDResolvesPerClient: both clients publish
// contractSharedKID, each for its own key; each gets exactly its own.
func checkContractSharedKeyIDResolvesPerClient(source ClientKeySource, f contractFixture) []string {
	var problems []string
	for _, id := range []fapi.ClientID{contractClientA, contractClientB} {
		want := f.key(id, contractSharedKID)
		set, err := source.ResolveVerificationKeys(context.Background(), ClientKeyRequest{
			ClientID: id, Purpose: ClientAssertionVerification, Algorithm: fapi.ES256, KeyID: contractSharedKID,
		})
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("client %q, shared kid: %v", id, err))
		case len(set.Keys) != 1 || !samePublicKey(want.pub, set.Keys[0].PublicKey):
			problems = append(problems, fmt.Sprintf("client %q, kid %q: got %d key(s), want exactly the client's own key", id, contractSharedKID, len(set.Keys)))
		}
	}
	return problems
}

// checkContractUnknownClientIsAnError: an unregistered client ID is an
// error, whether or not the request names a kid a registered client
// publishes.
func checkContractUnknownClientIsAnError(source ClientKeySource, _ contractFixture) []string {
	var problems []string
	for _, kid := range []string{"", contractKIDAES256, contractSharedKID} {
		set, err := source.ResolveVerificationKeys(context.Background(), ClientKeyRequest{
			ClientID: contractUnknownClient, Purpose: ClientAssertionVerification, Algorithm: fapi.ES256, KeyID: kid,
		})
		if err == nil {
			problems = append(problems, fmt.Sprintf("unregistered client, kid %q: no error (got %d key(s)), want an error", kid, len(set.Keys)))
		}
	}
	return problems
}

// checkContractFiltersByAlgorithm: only keys for the requested
// algorithm are returned, including none for an algorithm the client
// has no key for.
func checkContractFiltersByAlgorithm(source ClientKeySource, _ contractFixture) []string {
	cases := []struct {
		id   fapi.ClientID
		alg  fapi.SignatureAlgorithm
		kid  string
		want int
	}{
		{contractClientA, fapi.PS256, "", 1},
		{contractClientA, fapi.ES256, "", 2},
		{contractClientA, fapi.ES256, contractKIDAPS256, 0},
		{contractClientA, fapi.EdDSA, "", 0},
		{contractClientB, fapi.PS256, "", 0},
	}
	var problems []string
	for _, c := range cases {
		got := contractResolve(source, ClientKeyRequest{ClientID: c.id, Purpose: ClientAssertionVerification, Algorithm: c.alg, KeyID: c.kid})
		for _, k := range got {
			if k.Algorithm != c.alg {
				problems = append(problems, fmt.Sprintf("client %q, %v, kid %q: returned a %v key", c.id, c.alg, c.kid, k.Algorithm))
			}
		}
		if len(got) != c.want {
			problems = append(problems, fmt.Sprintf("client %q, %v, kid %q: got %d key(s), want %d", c.id, c.alg, c.kid, len(got), c.want))
		}
	}
	return problems
}

// checkContractEveryKeyBelongsToTheRequestingClient: whatever is asked,
// every key returned is one of the requesting client's own, and has the
// requested kid when one was requested.
func checkContractEveryKeyBelongsToTheRequestingClient(source ClientKeySource, f contractFixture) []string {
	kids := []string{"", contractKIDAES256, contractKIDAPS256, contractKIDBES256, contractSharedKID, "never-published"}
	var problems []string
	for _, id := range []fapi.ClientID{contractClientA, contractClientB} {
		for _, alg := range []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256, fapi.EdDSA} {
			for _, kid := range kids {
				got := contractResolve(source, ClientKeyRequest{ClientID: id, Purpose: RequestObjectVerification, Algorithm: alg, KeyID: kid})
				problems = append(problems, ownKeyProblems(f, id, kid, got)...)
			}
		}
	}
	return problems
}

// ownKeyProblems is what is wrong with got as client id's answer for
// kid: keys the client doesn't publish, or with another kid.
func ownKeyProblems(f contractFixture, id fapi.ClientID, kid string, got []VerificationKey) []string {
	var problems []string
	for _, k := range got {
		if !f.owns(id, k.PublicKey) {
			problems = append(problems, fmt.Sprintf("client %q, kid %q: returned a key the client doesn't publish", id, kid))
		}
		if kid != "" && k.KeyID != kid {
			problems = append(problems, fmt.Sprintf("client %q, kid %q: returned a key with kid %q", id, kid, k.KeyID))
		}
	}
	return problems
}

// checkContractResolvesOwnKey: a client's own key resolves, by its kid
// and with no kid.
func checkContractResolvesOwnKey(source ClientKeySource, f contractFixture) []string {
	var problems []string
	for _, c := range []struct {
		id  fapi.ClientID
		kid string
	}{{contractClientA, contractKIDAES256}, {contractClientA, contractKIDAPS256}, {contractClientB, contractKIDBES256}} {
		want := f.key(c.id, c.kid)
		for _, kid := range []string{c.kid, ""} {
			set, err := source.ResolveVerificationKeys(context.Background(), ClientKeyRequest{
				ClientID: c.id, Purpose: ClientAssertionVerification, Algorithm: want.alg, KeyID: kid,
			})
			switch {
			case err != nil:
				problems = append(problems, fmt.Sprintf("client %q, kid %q: %v", c.id, kid, err))
			case !containsPublicKey(set.Keys, verificationKeyPublic, want.pub):
				problems = append(problems, fmt.Sprintf("client %q, kid %q: the client's own key %q wasn't returned", c.id, kid, c.kid))
			}
		}
	}
	return problems
}
