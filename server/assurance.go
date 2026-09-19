package server

import (
	"fmt"

	"github.com/idfoundry/fapigo/keys"
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
	// module considers necessary for a real deployment:
	// Dependencies.Audit, and a storage.StoreAssurance declaration for
	// every store this package's own operations actually touch: Clients,
	// Transactions, Grants, Replay, Nonces (when configured — it's
	// otherwise a genuinely optional dependency, not a gap), the
	// opaque-token store (when Dependencies.AccessTokens is
	// OpaqueAccessTokens — a JWTAccessTokens issuer has no separate
	// store to check), Revocation (unless it's the explicit NoRevocation{}
	// decline, which asserts nothing to check), and Backchannel (when
	// CIBA is configured). Every declaration must assert at least
	// Durable, and AtomicConsume for whichever of those expose a
	// Consume/Redeem/UseOnce-style operation (Transactions, Grants,
	// Replay, Nonces, Backchannel — Clients is a plain lookup and the
	// opaque-token store and Revocation are plain create/lookup/mark
	// operations, none with anything to assert atomicity for). A store
	// that doesn't implement StoreAssurance at all is rejected rather
	// than assumed adequate — declaring capabilities is not optional
	// under this assurance level. When Config.HorizontallyScaled is also
	// true, every one of those same stores must additionally declare
	// CrossInstanceConsistent. This does not verify any declaration; see
	// storage.StoreAssurance's doc comment for why a store should also
	// run this package's contract test suite (storage.TestGrantStoreContract
	// and friends) against itself. The same "declaring capabilities is
	// not optional" stance applies to Dependencies.ClientKeys (always)
	// and ClientEncryptionKeys (when set): both must implement
	// keys.KeySourceAssurance and declare LiveFetchHardened — see that
	// interface's own doc comment for why a plain ClientKeySource/
	// ClientEncryptionKeySource has no structural way to tell a hardened
	// implementation from a naive one apart from this declaration.
	// Further checks (HSM-backed keys where required, and the rest of
	// the checklist ARCHITECTURE.md describes) will be added here as the
	// mechanisms to check them are built.
	AssuranceProduction
)

// checkStoreAssurance requires store to implement storage.StoreAssurance
// and to assert Durable (always), AtomicConsume (when requireAtomicConsume
// is true), and CrossInstanceConsistent (when requireCrossInstanceConsistent
// is true — Config.HorizontallyScaled).
func checkStoreAssurance(name string, store any, requireAtomicConsume, requireCrossInstanceConsistent bool) error {
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
	if requireCrossInstanceConsistent && !caps.CrossInstanceConsistent {
		return fmt.Errorf("server: dependencies: %s must declare CrossInstanceConsistent capability under AssuranceProduction with HorizontallyScaled", name)
	}
	return nil
}

// checkKeySourceAssurance requires source to implement
// keys.KeySourceAssurance and to declare LiveFetchHardened.
func checkKeySourceAssurance(name string, source any) error {
	asserter, ok := source.(keys.KeySourceAssurance)
	if !ok {
		return fmt.Errorf("server: dependencies: %s must implement keys.KeySourceAssurance under AssuranceProduction", name)
	}
	if !asserter.Capabilities().LiveFetchHardened {
		return fmt.Errorf("server: dependencies: %s must declare LiveFetchHardened capability under AssuranceProduction", name)
	}
	return nil
}
