package server

import (
	"fmt"

	"github.com/idfoundry/fapigo/storage"
)

// AssuranceLevel gates how strict New's validation of Config and
// Dependencies is.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development only — most importantly, it does not require an
	// AuditSink or a store that declares storage.StoreAssurance
	// capabilities.
	AssuranceDevelopment

	// AssuranceProduction rejects a configuration missing anything this
	// module considers necessary for a real deployment: Dependencies.Audit,
	// and — for Clients, Transactions, Grants and Replay — a
	// storage.StoreAssurance declaration asserting at least Durable (all
	// four) and AtomicConsume (Transactions, Grants and Replay, which
	// each expose a Consume/Redeem/UseOnce-style operation; Clients is a
	// plain lookup and has no such operation to assert atomicity for). A
	// store that doesn't implement StoreAssurance at all is rejected
	// rather than assumed adequate — declaring capabilities is not
	// optional under this assurance level. This does not verify the
	// declaration; see storage.StoreAssurance's doc comment for why a
	// store should also run this package's contract test suite
	// (storage.TestGrantStoreContract and friends) against itself.
	// Further checks (HSM-backed keys where required, and the rest of
	// the checklist ARCHITECTURE.md describes) will be added here as the
	// mechanisms to check them are built.
	AssuranceProduction
)

// checkStoreAssurance requires store to implement storage.StoreAssurance
// and to assert Durable (always) and AtomicConsume (when
// requireAtomicConsume is true).
func checkStoreAssurance(name string, store any, requireAtomicConsume bool) error {
	asserter, ok := store.(storage.StoreAssurance)
	if !ok {
		return fmt.Errorf("server: dependencies: %s must implement storage.StoreAssurance under AssuranceProduction", name)
	}
	caps := asserter.Capabilities()
	if !caps.Durable {
		return fmt.Errorf("server: dependencies: %s must declare Durable capability under AssuranceProduction", name)
	}
	if requireAtomicConsume && !caps.AtomicConsume {
		return fmt.Errorf("server: dependencies: %s must declare AtomicConsume capability under AssuranceProduction", name)
	}
	return nil
}
