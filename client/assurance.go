package client

import (
	"fmt"

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
	// against itself.
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
