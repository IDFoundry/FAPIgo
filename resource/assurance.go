package resource

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/idfoundry/fapigo/internal/depcheck"
	"github.com/idfoundry/fapigo/internal/dpopnonce"
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
	//     when its fapihttp client is HardenedForProduction: over
	//     fapihttp.NewClient's client, with no loopback exception;
	//     keys/ephemeral never does). An OpaqueAccessTokens' Store must
	//     implement storage.StoreAssurance and declare Durable, and its
	//     Audience must be set: a resource server "MUST refuse" a token
	//     issued for another (RFC 9700 §2.3), and without Audience it
	//     can't tell. JWTAccessTokens always requires one.
	//   - Dependencies.Replay must implement storage.StoreAssurance and
	//     declare Durable and AtomicConsume: a DPoP proof used twice is
	//     only refused if the store records each use atomically and keeps
	//     it. Dependencies.Nonces is required: a nonce store, which must
	//     implement it and declare Durable (a nonce is looked up, never
	//     consumed, so it has no atomicity to declare), or the explicit
	//     NoDPoPNonces{} decline.
	//   - Dependencies.Revocation must implement storage.StoreAssurance
	//     and declare Durable, or be NoRevocationUntilExpiry with a
	//     MaxTokenLifetime of at most 15 minutes. NoRevocation is refused:
	//     a token the authorization server revoked would stay usable here
	//     for however long it was issued for (FAPI 2.0 Security Profile
	//     §5.3.4).
	//   - Dependencies.Clock must declare ClockAssurance (SystemClock
	//     does), and read within Limits.MaxClockSkew of time.Now when
	//     NewVerifier runs: a fixed or offset test clock would accept
	//     tokens and proofs long expired.
	//   - Dependencies.Random, when Nonces is a nonce store, must be
	//     crypto/rand.Reader itself: every DPoP nonce this verifier
	//     issues is only as unguessable as that reader.
	//   - Limits.MaxClockSkew must be between 10 and 60 seconds, as
	//     server.New requires (FAPI 2.0 Security Profile §5.3.2.1);
	//     MaxDPoPProofAge at most 5 minutes (RFC 9449 §11.1's "seconds or
	//     minutes"); and DPoPNonceLifetime at most 15 minutes.
	//
	// Config.Deployment is required: with DeploymentHorizontallyScaled,
	// every store checked above must also declare CrossInstanceConsistent. As with server.New, a store
	// that doesn't implement storage.StoreAssurance at all is refused
	// rather than assumed adequate, and nothing verifies a declaration:
	// a store should also run the storage package's contract tests
	// against itself.
	AssuranceProduction
)

// Deployment says whether one verifier instance, or a fleet of them,
// uses the storage tier. It's required under AssuranceProduction, where
// it decides whether every store AssuranceProduction checks must also
// declare CrossInstanceConsistent: the zero value is refused there, so a
// fleet can't forget to say so and be checked as a single instance.
// Under AssuranceDevelopment it may be left zero, and is ignored.
type Deployment uint8

const (
	_ Deployment = iota

	// DeploymentSingleInstance is one process using the storage tier:
	// stores needn't be consistent across instances.
	DeploymentSingleInstance

	// DeploymentHorizontallyScaled is more than one process sharing the
	// storage tier. Under AssuranceProduction, every store checked must
	// also declare CrossInstanceConsistent.
	DeploymentHorizontallyScaled
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
	// CrossInstanceConsistent with DeploymentHorizontallyScaled), as
	// OpaqueAccessTokens.Store must.
	Store any
}

// The clock skew AssuranceProduction allows, as server.New does: FAPI
// 2.0 Security Profile §5.3.2.1 has iat and nbf up to 10 seconds in the
// future accepted and more than 60 seconds refused, and here the skew
// also bounds how long past exp a token is still accepted.
const (
	fapiMinClockSkew = 10 * time.Second
	fapiMaxClockSkew = 60 * time.Second
)

// The DPoP windows AssuranceProduction bounds, as server.New does: RFC
// 9449 §11.1 has a proof accepted "only for a relatively brief period on
// the order of seconds or minutes", and a nonce, which RFC 9449 gives no
// number, limits how long a proof made for it stays usable.
const (
	fapiMaxDPoPProofAge      = 5 * time.Minute
	fapiMaxDPoPNonceLifetime = 15 * time.Minute
)

// validateAssurance checks the assurance level is one of the two
// defined, and applies AssuranceProduction's checks — reporting every
// dependency that falls short, joined (errors.Join), rather than only
// the first, so a deployment moving to production sees the whole list
// in one restart.
func validateAssurance(cfg Config, deps Dependencies) error {
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return fmt.Errorf("resource: config: assurance level is invalid")
	}
	switch cfg.Deployment {
	case DeploymentSingleInstance, DeploymentHorizontallyScaled:
	case 0:
		if cfg.Assurance == AssuranceProduction {
			return fmt.Errorf("resource: config: deployment is required under AssuranceProduction (DeploymentSingleInstance or DeploymentHorizontallyScaled)")
		}
	default:
		return fmt.Errorf("resource: config: deployment is invalid")
	}
	if cfg.Assurance != AssuranceProduction {
		return nil
	}
	scaled := cfg.Deployment == DeploymentHorizontallyScaled
	errs := checkProductionAccessTokens(deps.AccessTokens, scaled)
	errs = append(errs, productionLimitErrors(cfg.Limits)...)
	errs = append(errs, checkClock(deps.Clock, cfg.Limits.MaxClockSkew))
	errs = append(errs, checkStoreAssurance("replay", deps.Replay, true, scaled))
	errs = append(errs, checkProductionNonces(deps, scaled)...)
	errs = append(errs, checkProductionRevocation(deps.Revocation, scaled))
	if deps.PairwiseSubjects != nil {
		errs = append(errs, checkKeyCustody("pairwise_subjects", deps.PairwiseSubjects, scaled))
	}
	if deps.PairwiseSubjectResolver != nil {
		errs = append(errs, checkKeyCustody("subject_resolver", deps.PairwiseSubjectResolver, scaled))
	}
	return errors.Join(errs...)
}

// checkProductionNonces requires a nonce store, declaring
// StoreAssurance, with Random from crypto/rand, unless nonces were
// declined with NoDPoPNonces.
func checkProductionNonces(deps Dependencies, scaled bool) []error {
	switch {
	case deps.Nonces == nil:
		return []error{errors.New("resource: dependencies: nonces is required under AssuranceProduction (pass a storage.NonceStore, with Random and Limits.DPoPNonceLifetime, to challenge DPoP proofs for a nonce, or NoDPoPNonces{} to explicitly decline)")}
	case dpopnonce.Declined[NoDPoPNonces](deps.Nonces):
		return nil
	}
	return []error{checkStoreAssurance("nonces", deps.Nonces, false, scaled), checkRandom(deps.Random)}
}

// productionLimitErrors checks Limits against AssuranceProduction's
// bounds, reporting every one exceeded.
func productionLimitErrors(l Limits) []error {
	var errs []error
	if l.MaxClockSkew < fapiMinClockSkew || l.MaxClockSkew > fapiMaxClockSkew {
		errs = append(errs, fmt.Errorf("resource: config: limits.max_clock_skew must be between %v and %v under AssuranceProduction (FAPI 2.0 §5.3.2.1)", fapiMinClockSkew, fapiMaxClockSkew))
	}
	if l.MaxDPoPProofAge > fapiMaxDPoPProofAge {
		errs = append(errs, fmt.Errorf("resource: config: limits.max_dpop_proof_age must be at most %v under AssuranceProduction (RFC 9449 §11.1)", fapiMaxDPoPProofAge))
	}
	if l.DPoPNonceLifetime > fapiMaxDPoPNonceLifetime {
		errs = append(errs, fmt.Errorf("resource: config: limits.dpop_nonce_lifetime must be at most %v under AssuranceProduction", fapiMaxDPoPNonceLifetime))
	}
	return errs
}

// checkClock requires clock to declare ClockAssurance, and its reading
// to be within skew of the system's time now.
func checkClock(clock Clock, skew time.Duration) error {
	if !depcheck.ReadsSystemTime(clock) {
		return fmt.Errorf("resource: dependencies: clock must be SystemClock, or declare resource.ClockAssurance, under AssuranceProduction")
	}
	if offset := depcheck.ClockOffset(clock.Now()); offset > skew {
		return fmt.Errorf("resource: dependencies: clock reads %v away from the system's time, more than limits.max_clock_skew (%v), under AssuranceProduction", offset.Round(time.Second), skew)
	}
	return nil
}

// checkProductionRevocation refuses NoRevocation, accepts
// NoRevocationUntilExpiry declaring at most 15 minutes, and otherwise
// requires the checker's store to declare Durable.
func checkProductionRevocation(revocation RevocationChecker, scaled bool) error {
	if declinedRevocation(revocation) {
		return fmt.Errorf("resource: dependencies: revocation is NoRevocation, which AssuranceProduction refuses (FAPI 2.0 §5.3.4): check the authorization server's revocation store, or decline with NoRevocationUntilExpiry and a MaxTokenLifetime of at most %v", maxUnrevocableTokenLifetime)
	}
	if lifetime, ok := unrevocableLifetime(revocation); ok {
		if lifetime > maxUnrevocableTokenLifetime {
			return fmt.Errorf("resource: dependencies: revocation's NoRevocationUntilExpiry.MaxTokenLifetime must be at most %v under AssuranceProduction", maxUnrevocableTokenLifetime)
		}
		return nil
	}
	return checkStoreAssurance("revocation", revocation, false, scaled)
}

// checkProductionAccessTokens checks what resolver relies on: the
// issuer key source and the token store it names.
func checkProductionAccessTokens(resolver AccessTokenResolver, scaled bool) []error {
	declared, err := productionAccessTokenAssurance(resolver)
	if err != nil {
		return []error{err}
	}
	var errs []error
	if opaqueWithoutAudience(resolver) {
		errs = append(errs, fmt.Errorf("resource: dependencies: access_tokens' OpaqueAccessTokens.Audience is required under AssuranceProduction (RFC 9700 §2.3): set it to this resource server's identifier, or to the issuer's when it has none"))
	}
	if declared.IssuerKeys != nil {
		errs = append(errs, checkKeySourceAssurance("access_tokens issuer keys", declared.IssuerKeys))
	}
	if declared.Store != nil {
		errs = append(errs, checkStoreAssurance("access_tokens", declared.Store, false, scaled))
	}
	return errs
}

// opaqueWithoutAudience reports whether resolver is an
// OpaqueAccessTokens, by value or pointer, that checks no audience.
func opaqueWithoutAudience(resolver AccessTokenResolver) bool {
	switch t := resolver.(type) {
	case OpaqueAccessTokens:
		return t.Audience == ""
	case *OpaqueAccessTokens:
		return t != nil && t.Audience == ""
	}
	return false
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
// requireCrossInstanceConsistent — Config.Deployment is DeploymentHorizontallyScaled).
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
		return fmt.Errorf("resource: dependencies: %s must declare CrossInstanceConsistent capability under AssuranceProduction with DeploymentHorizontallyScaled", name)
	}
	return nil
}

// checkKeyCustody requires a pairwise lookup to implement
// keys.KeyCustodyAssurance and to declare Durable (always) and
// CrossInstanceConsistent (when requireCrossInstanceConsistent):
// every instance must map a pairwise sub back to the same end user, as
// long as the tokens carrying it are valid.
func checkKeyCustody(name string, lookup any, requireCrossInstanceConsistent bool) error {
	asserter, ok := lookup.(keys.KeyCustodyAssurance)
	if !ok {
		return fmt.Errorf("resource: dependencies: %s must implement keys.KeyCustodyAssurance under AssuranceProduction", name)
	}
	custody := asserter.KeyCustody()
	if !custody.Durable {
		return fmt.Errorf("resource: dependencies: %s must declare Durable custody under AssuranceProduction", name)
	}
	if requireCrossInstanceConsistent && !custody.CrossInstanceConsistent {
		return fmt.Errorf("resource: dependencies: %s must declare CrossInstanceConsistent custody under AssuranceProduction with DeploymentHorizontallyScaled", name)
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
