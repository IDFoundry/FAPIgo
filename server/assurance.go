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
	// capabilities. It also accepts a web client's loopback http redirect
	// URIs (RFC 8252 §7.3, e.g. "http://localhost:8080/callback"), which
	// AssuranceProduction refuses at the pushed authorization request. A
	// client registered as storage.ApplicationTypeNative may use loopback
	// http, and a private-use scheme, under either level.
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
	// With CIBA configured, Dependencies.BackchannelNotifier must
	// implement BackchannelNotifierAssurance and declare
	// OutboundHardened (backchannelhttp.Notifier and
	// NoBackchannelNotifications do), since it sends to client-supplied
	// notification endpoints.
	// Dependencies.Random must be crypto/rand.Reader itself: every
	// request_uri, authorization code, refresh token, opaque access
	// token, jti and DPoP nonce this server issues is only as
	// unguessable as that reader, and nothing about an io.Reader says
	// whether it is a CSPRNG.
	// The issuer, every Endpoints URL and every Config.MTLSEndpoints
	// alias must be https: one parsed with fapi.AllowLoopbackHTTP is
	// refused.
	// Unlike every check above, which New performs once, a web client's
	// loopback http redirect URI is refused per request, at the pushed
	// authorization request, as invalid_request — redirect URIs belong
	// to client registrations, which New never sees. A native client's
	// (storage.ApplicationTypeNative) is accepted, as FAPI 2.0 allows.
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

// checkNotifierAssurance requires notifier to implement
// BackchannelNotifierAssurance and to declare OutboundHardened.
func checkNotifierAssurance(notifier BackchannelNotifier) error {
	asserter, ok := notifier.(BackchannelNotifierAssurance)
	if !ok {
		return fmt.Errorf("server: dependencies: backchannel notifier must implement server.BackchannelNotifierAssurance under AssuranceProduction (backchannelhttp.Notifier does)")
	}
	if !asserter.BackchannelNotifierCapabilities().OutboundHardened {
		return fmt.Errorf("server: dependencies: backchannel notifier must declare OutboundHardened capability under AssuranceProduction")
	}
	return nil
}

// AccessTokenIssuerAssurance is implemented by an AccessTokenIssuer of
// the application's own to declare, under AssuranceProduction, what it
// relies on, so New can check it the way it checks JWTAccessTokens and
// OpaqueAccessTokens. New refuses any other AccessTokenIssuer under
// AssuranceProduction: an issuer it can't see into would otherwise skip
// the key custody and store checks entirely. A type embedding
// JWTAccessTokens needn't implement it; its keys are checked as
// JWTAccessTokens' are.
type AccessTokenIssuerAssurance interface {
	AccessTokenAssurance() AccessTokenAssurance
}

// AccessTokenAssurance is what a custom AccessTokenIssuer relies on. At
// least one field must be set.
type AccessTokenAssurance struct {
	// SigningKeys signs the access tokens, if they're signed. Under
	// AssuranceProduction it must implement keys.KeyCustodyAssurance and
	// declare Durable key custody (and CrossInstanceConsistent with
	// HorizontallyScaled), as Dependencies.Keys must.
	SigningKeys keys.KeyManager

	// Store keeps the access tokens, if they're kept (opaque tokens).
	// Under AssuranceProduction it must implement storage.StoreAssurance
	// and declare Durable (and CrossInstanceConsistent with
	// HorizontallyScaled), as OpaqueAccessTokens.Store must.
	Store any
}

// productionAccessTokenAssurance returns what issuer relies on, for the
// AssuranceProduction checks: JWTAccessTokens' signing keys and
// OpaqueAccessTokens' store, by value or pointer; the signing keys of a
// type embedding JWTAccessTokens; or a custom issuer's own
// AccessTokenIssuerAssurance declaration. Any other issuer is refused.
func productionAccessTokenAssurance(issuer AccessTokenIssuer) (AccessTokenAssurance, error) {
	switch t := issuer.(type) {
	case JWTAccessTokens:
		return AccessTokenAssurance{SigningKeys: t.Keys}, nil
	case *JWTAccessTokens:
		if t == nil {
			return AccessTokenAssurance{}, fmt.Errorf("server: dependencies: access_tokens is a nil *JWTAccessTokens")
		}
		return AccessTokenAssurance{SigningKeys: t.Keys}, nil
	case OpaqueAccessTokens:
		return AccessTokenAssurance{Store: t.Store}, nil
	case *OpaqueAccessTokens:
		if t == nil {
			return AccessTokenAssurance{}, fmt.Errorf("server: dependencies: access_tokens is a nil *OpaqueAccessTokens")
		}
		return AccessTokenAssurance{Store: t.Store}, nil
	case AccessTokenIssuerAssurance:
		declared := t.AccessTokenAssurance()
		if declared.SigningKeys == nil && declared.Store == nil {
			return AccessTokenAssurance{}, fmt.Errorf("server: dependencies: access_tokens' AccessTokenAssurance must name its SigningKeys or Store under AssuranceProduction")
		}
		return declared, nil
	case accessTokenKeyPublisher:
		return AccessTokenAssurance{SigningKeys: t.accessTokenSigningKeyUse().Manager}, nil
	}
	return AccessTokenAssurance{}, fmt.Errorf("server: dependencies: access_tokens must be JWTAccessTokens, OpaqueAccessTokens, or implement server.AccessTokenIssuerAssurance under AssuranceProduction")
}
