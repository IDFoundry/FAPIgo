package server

import (
	"crypto/rand"
	"fmt"
	"io"

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
	// capabilities. It also accepts loopback http redirect URIs
	// (RFC 8252 §7.3, e.g. "http://localhost:8080/callback"), which
	// AssuranceProduction refuses at the pushed authorization request.
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
	// Likewise the keys this server signs with — Dependencies.Keys, and
	// JWTAccessTokens.Keys when access tokens are JWTs — must implement
	// keys.KeyCustodyAssurance and declare Durable (and
	// CrossInstanceConsistent with HorizontallyScaled): keys/ephemeral's
	// in-memory keys, regenerated on every restart, never qualify. An
	// HSM or KMS is not required — durable keys a deployment loads from
	// its own storage qualify too — only that the declaration is made.
	// Dependencies.Random must be crypto/rand.Reader itself: every
	// request_uri, authorization code, refresh token, opaque access
	// token, jti and DPoP nonce this server issues is only as
	// unguessable as that reader, and nothing about an io.Reader says
	// whether it is a CSPRNG.
	// Unlike every check above, which New performs once, a client's
	// loopback http redirect URI is refused per request, at the pushed
	// authorization request, as invalid_request — redirect URIs belong
	// to client registrations, which New never sees.
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

// checkRandom requires random to be crypto/rand.Reader itself.
func checkRandom(random io.Reader) error {
	if random != rand.Reader {
		return fmt.Errorf("server: dependencies: random must be crypto/rand.Reader under AssuranceProduction")
	}
	return nil
}

// checkKeyCustody requires manager — a keys.KeyManager or
// keys.Decrypter — to implement keys.KeyCustodyAssurance and to declare
// Durable, and CrossInstanceConsistent when requireCrossInstanceConsistent.
func checkKeyCustody(name string, manager any, requireCrossInstanceConsistent bool) error {
	asserter, ok := manager.(keys.KeyCustodyAssurance)
	if !ok {
		return fmt.Errorf("server: dependencies: %s must implement keys.KeyCustodyAssurance under AssuranceProduction (keys/ephemeral never does; pass keys.DeclareCustody to keys.NewKeyManagerFromSigners)", name)
	}
	custody := asserter.KeyCustody()
	if !custody.Durable {
		return fmt.Errorf("server: dependencies: %s must declare Durable key custody under AssuranceProduction", name)
	}
	if requireCrossInstanceConsistent && !custody.CrossInstanceConsistent {
		return fmt.Errorf("server: dependencies: %s must declare CrossInstanceConsistent key custody under AssuranceProduction with HorizontallyScaled", name)
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
