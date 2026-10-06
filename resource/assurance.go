package resource

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AssuranceLevel gates how strict NewVerifier's validation of Config
// and Dependencies is, as server.AssuranceLevel does for server.New.
// The zero value is refused: a verifier must say which it is.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development and testing only: in-memory stores and key sources
	// that declare no capabilities (storage/memstore, keys/ephemeral).
	AssuranceDevelopment

	// AssuranceProduction rejects a configuration missing anything this
	// module considers necessary for a real deployment:
	//
	//   - Dependencies.AccessTokens must be JWTAccessTokens,
	//     OpaqueAccessTokens, or implement AccessTokenResolverAssurance.
	//     A JWTAccessTokens' IssuerKeys must implement
	//     keys.KeySourceAssurance and declare LiveFetchHardened (as
	//     keys.LocalIssuerKeys does, and keys.JWKSIssuerKeySource does
	//     when its fapihttp client grants no loopback exception;
	//     keys/ephemeral never does). An OpaqueAccessTokens' Store must
	//     implement storage.StoreAssurance and declare Durable.
	//   - Dependencies.Replay, and Dependencies.Nonces when set, must
	//     implement storage.StoreAssurance and declare Durable and
	//     AtomicConsume: a DPoP proof or nonce used twice is only
	//     refused if the store records each use atomically and keeps it.
	//   - Dependencies.Revocation must implement storage.StoreAssurance
	//     and declare Durable, unless it is NoRevocation, the explicit
	//     decline.
	//   - Dependencies.Random, when Nonces is set, must be
	//     crypto/rand.Reader itself: every DPoP nonce this verifier
	//     issues is only as unguessable as that reader.
	//
	// With Config.HorizontallyScaled, every store checked above must
	// also declare CrossInstanceConsistent. As with server.New, a store
	// that doesn't implement storage.StoreAssurance at all is refused
	// rather than assumed adequate, and nothing verifies a declaration:
	// a store should also run the storage package's contract tests
	// against itself.
	AssuranceProduction
)

// AccessTokenResolverAssurance is implemented by an AccessTokenResolver
// of the application's own to declare, under AssuranceProduction, what
// it relies on, so NewVerifier can check it the way it checks
// JWTAccessTokens and OpaqueAccessTokens. NewVerifier refuses any other
// AccessTokenResolver under AssuranceProduction: a resolver it can't
// see into would otherwise skip the key source and store checks
// entirely. Mirrors server.AccessTokenIssuerAssurance.
type AccessTokenResolverAssurance interface {
	AccessTokenAssurance() AccessTokenAssurance
}

// AccessTokenAssurance is what a custom AccessTokenResolver relies on.
// At least one field must be set.
type AccessTokenAssurance struct {
	// IssuerKeys verifies the access tokens, if they're signed. Under
	// AssuranceProduction it must implement keys.KeySourceAssurance and
	// declare LiveFetchHardened, as JWTAccessTokens.IssuerKeys must.
	IssuerKeys keys.IssuerKeySource

	// Store looks the access tokens up, if they're kept (opaque
	// tokens). Under AssuranceProduction it must implement
	// storage.StoreAssurance and declare Durable (and
	// CrossInstanceConsistent with HorizontallyScaled), as
	// OpaqueAccessTokens.Store must.
	Store any
}

// validateAssurance checks the assurance level is one of the two
// defined, and applies AssuranceProduction's checks.
func validateAssurance(cfg Config, deps Dependencies) error {
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return fmt.Errorf("resource: config: assurance level is invalid")
	}
	if cfg.Assurance != AssuranceProduction {
		return nil
	}
	scaled := cfg.HorizontallyScaled
	if err := checkProductionAccessTokens(deps.AccessTokens, scaled); err != nil {
		return err
	}
	if err := checkStoreAssurance("replay", deps.Replay, true, scaled); err != nil {
		return err
	}
	if deps.Nonces != nil {
		if err := checkStoreAssurance("nonces", deps.Nonces, true, scaled); err != nil {
			return err
		}
		if err := checkRandom(deps.Random); err != nil {
			return err
		}
	}
	if !declinedRevocation(deps.Revocation) {
		return checkStoreAssurance("revocation", deps.Revocation, false, scaled)
	}
	return nil
}

// checkProductionAccessTokens checks what resolver relies on: the
// issuer key source and the token store it names.
func checkProductionAccessTokens(resolver AccessTokenResolver, scaled bool) error {
	declared, err := productionAccessTokenAssurance(resolver)
	if err != nil {
		return err
	}
	if declared.IssuerKeys != nil {
		if err := checkKeySourceAssurance("access_tokens issuer keys", declared.IssuerKeys); err != nil {
			return err
		}
	}
	if declared.Store != nil {
		return checkStoreAssurance("access_tokens", declared.Store, false, scaled)
	}
	return nil
}

// productionAccessTokenAssurance returns what resolver relies on:
// JWTAccessTokens' issuer keys and OpaqueAccessTokens' store, by value
// or pointer, or a custom resolver's own AccessTokenResolverAssurance
// declaration. Any other resolver is refused.
func productionAccessTokenAssurance(resolver AccessTokenResolver) (AccessTokenAssurance, error) {
	switch t := resolver.(type) {
	case JWTAccessTokens:
		return AccessTokenAssurance{IssuerKeys: t.IssuerKeys}, nil
	case *JWTAccessTokens:
		if t == nil {
			return AccessTokenAssurance{}, fmt.Errorf("resource: dependencies: access_tokens is a nil *JWTAccessTokens")
		}
		return AccessTokenAssurance{IssuerKeys: t.IssuerKeys}, nil
	case OpaqueAccessTokens:
		return AccessTokenAssurance{Store: t.Store}, nil
	case *OpaqueAccessTokens:
		if t == nil {
			return AccessTokenAssurance{}, fmt.Errorf("resource: dependencies: access_tokens is a nil *OpaqueAccessTokens")
		}
		return AccessTokenAssurance{Store: t.Store}, nil
	case AccessTokenResolverAssurance:
		declared := t.AccessTokenAssurance()
		if declared.IssuerKeys == nil && declared.Store == nil {
			return AccessTokenAssurance{}, fmt.Errorf("resource: dependencies: access_tokens' AccessTokenAssurance must name its IssuerKeys or Store under AssuranceProduction")
		}
		return declared, nil
	}
	return AccessTokenAssurance{}, fmt.Errorf("resource: dependencies: access_tokens must be JWTAccessTokens, OpaqueAccessTokens, or implement resource.AccessTokenResolverAssurance under AssuranceProduction")
}

// checkStoreAssurance requires store to implement storage.StoreAssurance
// and to assert Durable (always), AtomicConsume (when
// requireAtomicConsume), and CrossInstanceConsistent (when
// requireCrossInstanceConsistent — Config.HorizontallyScaled).
func checkStoreAssurance(name string, store any, requireAtomicConsume, requireCrossInstanceConsistent bool) error {
	asserter, ok := store.(storage.StoreAssurance)
	if !ok {
		return fmt.Errorf("resource: dependencies: %s must implement storage.StoreAssurance under AssuranceProduction", name)
	}
	caps := asserter.Capabilities()
	if !caps.Durable {
		return fmt.Errorf("resource: dependencies: %s must declare Durable capability under AssuranceProduction", name)
	}
	if requireAtomicConsume && !caps.AtomicConsume {
		return fmt.Errorf("resource: dependencies: %s must declare AtomicConsume capability under AssuranceProduction", name)
	}
	if requireCrossInstanceConsistent && !caps.CrossInstanceConsistent {
		return fmt.Errorf("resource: dependencies: %s must declare CrossInstanceConsistent capability under AssuranceProduction with HorizontallyScaled", name)
	}
	return nil
}

// checkKeySourceAssurance requires source to implement
// keys.KeySourceAssurance and to declare LiveFetchHardened.
func checkKeySourceAssurance(name string, source any) error {
	asserter, ok := source.(keys.KeySourceAssurance)
	if !ok {
		return fmt.Errorf("resource: dependencies: %s must implement keys.KeySourceAssurance under AssuranceProduction", name)
	}
	if !asserter.Capabilities().LiveFetchHardened {
		return fmt.Errorf("resource: dependencies: %s must declare LiveFetchHardened capability under AssuranceProduction", name)
	}
	return nil
}

// checkRandom requires random to be crypto/rand.Reader itself.
func checkRandom(random io.Reader) error {
	if random != rand.Reader {
		return fmt.Errorf("resource: dependencies: random must be crypto/rand.Reader under AssuranceProduction")
	}
	return nil
}

// declinedRevocation reports whether revocation is NoRevocation, by
// value or pointer.
func declinedRevocation(revocation RevocationChecker) bool {
	switch revocation.(type) {
	case NoRevocation, *NoRevocation:
		return true
	}
	return false
}
