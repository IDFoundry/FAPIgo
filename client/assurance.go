package client

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AssuranceLevel gates how strict New's validation of Dependencies is —
// mirrors server.AssuranceLevel exactly, for the identical reason: an
// in-memory Dependencies.Sessions (memstore.NewSessionStore(), the
// obvious first choice for a new integration) has the same
// non-durable, unbounded-growth profile server.New already refuses
// under AssuranceProduction, but client.New previously asked no such
// question at all.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development only — most importantly, it does not require
	// Dependencies.Sessions to declare storage.StoreAssurance
	// capabilities.
	AssuranceDevelopment

	// AssuranceProduction rejects a Dependencies.Sessions that doesn't
	// declare storage.StoreAssurance capabilities asserting at least
	// Durable and AtomicConsume. SessionStore.Consume is a single-use
	// check-and-retire operation — the same category
	// server.AssuranceProduction already requires AtomicConsume for
	// (Transactions, Grants, Replay) — so a store that doesn't
	// implement StoreAssurance at all is rejected rather than assumed
	// adequate, exactly like server's own rule. This does not verify
	// the declaration; see storage.StoreAssurance's own doc comment
	// for why a store should also run storage.TestSessionStoreContract
	// against itself. The same "declaring capabilities is not optional"
	// stance applies to Dependencies.IssuerKeys: it must implement
	// keys.KeySourceAssurance and declare LiveFetchHardened — see that
	// interface's own doc comment for why a plain IssuerKeySource has no
	// structural way to tell a hardened implementation from a naive one
	// apart from this declaration. Likewise Dependencies.Keys, and
	// Dependencies.Decryption when set, must implement
	// keys.KeyCustodyAssurance and declare Durable: keys/ephemeral's
	// in-memory keys, regenerated on every restart, never qualify.
	// Dependencies.Random must be crypto/rand.Reader itself: state,
	// nonce, PKCE verifiers and every jti this client signs are only as
	// unguessable as that reader, and nothing about an io.Reader says
	// whether it is a CSPRNG.
	// The issuer and every Endpoints URL must be https (one parsed with
	// fapi.AllowLoopbackHTTP is refused), and ProtectedResource's Do
	// refuses a loopback http resource URL before sending anything. A
	// native app's loopback redirect URI is unaffected.
	AssuranceProduction
)

// checkStoreAssurance requires store to implement storage.StoreAssurance
// and to assert Durable and AtomicConsume — mirrors server's own
// helper of the same name and signature (minus requireAtomicConsume,
// since Sessions is client's only store-shaped dependency and always
// needs it).
func checkStoreAssurance(name string, store any) error {
	asserter, ok := store.(storage.StoreAssurance)
	if !ok {
		return fmt.Errorf("client: dependencies: %s must implement storage.StoreAssurance under AssuranceProduction", name)
	}
	caps := asserter.Capabilities()
	if !caps.Durable {
		return fmt.Errorf("client: dependencies: %s must declare Durable capability under AssuranceProduction", name)
	}
	if !caps.AtomicConsume {
		return fmt.Errorf("client: dependencies: %s must declare AtomicConsume capability under AssuranceProduction", name)
	}
	return nil
}

// checkRandom requires random to be crypto/rand.Reader itself.
func checkRandom(random io.Reader) error {
	if random != rand.Reader {
		return fmt.Errorf("client: dependencies: random must be crypto/rand.Reader itself under AssuranceProduction: pass it directly, not a wrapper, which nothing can verify reads a CSPRNG")
	}
	return nil
}

// checkKeyCustody requires manager — a keys.KeyManager or
// keys.Decrypter — to implement keys.KeyCustodyAssurance and declare
// Durable, mirroring server's own helper.
func checkKeyCustody(name string, manager any) error {
	asserter, ok := manager.(keys.KeyCustodyAssurance)
	if !ok {
		return fmt.Errorf("client: dependencies: %s must implement keys.KeyCustodyAssurance under AssuranceProduction (keys/ephemeral never does; pass keys.DeclareCustody to keys.NewKeyManagerFromSigners)", name)
	}
	if !asserter.KeyCustody().Durable {
		return fmt.Errorf("client: dependencies: %s must declare Durable key custody under AssuranceProduction", name)
	}
	return nil
}

// checkKeySourceAssurance requires source to implement
// keys.KeySourceAssurance and to declare LiveFetchHardened — mirrors
// server's own helper of the same name and signature.
func checkKeySourceAssurance(name string, source any) error {
	asserter, ok := source.(keys.KeySourceAssurance)
	if !ok {
		return fmt.Errorf("client: dependencies: %s must implement keys.KeySourceAssurance under AssuranceProduction", name)
	}
	if !asserter.Capabilities().LiveFetchHardened {
		return fmt.Errorf("client: dependencies: %s must declare LiveFetchHardened capability under AssuranceProduction", name)
	}
	return nil
}
