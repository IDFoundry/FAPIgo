package keys

import (
	"context"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// contractSourceFunc adapts a function to ClientKeySource.
type contractSourceFunc func(ClientKeyRequest) (VerificationKeySet, error)

func (f contractSourceFunc) ResolveVerificationKeys(_ context.Context, req ClientKeyRequest) (VerificationKeySet, error) {
	return f(req)
}

// allContractKeys is every key of every fixture client, as
// VerificationKeys.
func allContractKeys(f contractFixture) []VerificationKey {
	var out []VerificationKey
	for _, id := range []fapi.ClientID{contractClientA, contractClientB} {
		for _, k := range f.keys[id] {
			out = append(out, VerificationKey{KeyID: k.kid, Algorithm: k.alg, PublicKey: k.pub})
		}
	}
	return out
}

// TestContractChecksCatchBrokenSources: each kind of broken source
// fails the checks that exist to catch it, and a correct one passes all
// of them — run in-process, so the checks' failure reporting is itself
// tested.
func TestContractChecksCatchBrokenSources(t *testing.T) {
	f := newContractFixture(t)
	every := allContractKeys(f)
	material := map[fapi.ClientID]ClientKeyMaterial{}
	for id, doc := range f.documents(t) {
		material[id] = ClientKeyMaterial{JWKS: doc}
	}
	static, err := NewStaticClientKeys(material)
	if err != nil {
		t.Fatalf("NewStaticClientKeys: %v", err)
	}

	sources := []struct {
		name       string
		source     ClientKeySource
		wantFailed []string
	}{
		{name: "correct", source: static},
		{
			name: "kid-indexed across clients",
			source: contractSourceFunc(func(req ClientKeyRequest) (VerificationKeySet, error) {
				for _, k := range every {
					if k.KeyID == req.KeyID && k.Algorithm == req.Algorithm {
						return VerificationKeySet{Keys: []VerificationKey{k}}, nil
					}
				}
				return VerificationKeySet{}, errors.New("unknown kid")
			}),
			wantFailed: []string{"KeyIDNeverResolvesForAnotherClient", "SharedKeyIDResolvesPerClient", "UnknownClientIsAnError", "FiltersByAlgorithm", "EveryKeyBelongsToTheRequestingClient", "ResolvesOwnKey"},
		},
		{
			name: "returns every key, unfiltered",
			source: contractSourceFunc(func(ClientKeyRequest) (VerificationKeySet, error) {
				return VerificationKeySet{Keys: every}, nil
			}),
			wantFailed: []string{"KeyIDNeverResolvesForAnotherClient", "SharedKeyIDResolvesPerClient", "UnknownClientIsAnError", "FiltersByAlgorithm", "EveryKeyBelongsToTheRequestingClient"},
		},
		{
			name: "always fails",
			source: contractSourceFunc(func(ClientKeyRequest) (VerificationKeySet, error) {
				return VerificationKeySet{}, errors.New("down")
			}),
			wantFailed: []string{"SharedKeyIDResolvesPerClient", "FiltersByAlgorithm", "ResolvesOwnKey"},
		},
	}
	for _, s := range sources {
		t.Run(s.name, func(t *testing.T) { checkContractOutcome(t, s.source, f, s.wantFailed) })
	}
}

func checkContractOutcome(t *testing.T, source ClientKeySource, f contractFixture, wantFailed []string) {
	t.Helper()
	want := map[string]bool{}
	for _, name := range wantFailed {
		want[name] = true
	}
	for _, c := range contractChecks {
		problems := c.check(source, f)
		if failed := len(problems) > 0; failed != want[c.name] {
			t.Errorf("%s: failed = %v (%q), want %v", c.name, failed, problems, want[c.name])
		}
	}
}
