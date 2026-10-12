package server

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/pairwise"
)

// SubjectTypeEnforcement is whether a client's own subject type
// (storage.RegisteredClientConfig.SubjectType) may override
// SubjectConfig.Default. Its zero value is no enforcement at all, which
// New refuses: the choice is stated, never defaulted.
type SubjectTypeEnforcement uint8

const (
	_ SubjectTypeEnforcement = iota

	// SubjectTypesPerClient lets a client's registered subject type
	// override SubjectConfig.Default, either way.
	SubjectTypesPerClient

	// SubjectTypesPairwiseOnly gives every end user a pairwise sub at
	// every client: a client registered as public is refused, so no
	// client can opt out. It requires a pairwise Default.
	SubjectTypesPairwiseOnly
)

// IsValid reports whether e is SubjectTypesPerClient or
// SubjectTypesPairwiseOnly.
func (e SubjectTypeEnforcement) IsValid() bool {
	return e == SubjectTypesPerClient || e == SubjectTypesPairwiseOnly
}

// SubjectConfig is Config.Subjects: the kind of sub this server's end
// users get at each client (OpenID Connect Core §8). Every field's zero
// value is invalid where the field applies, so a deployment states each
// choice:
//
//   - Default is the subject type of a client that doesn't register its
//     own: fapi.SubjectTypePublic, every client sees the same sub, as
//     before this setting existed; or fapi.SubjectTypePairwise, each
//     sector of clients sees its own.
//   - Enforcement is whether a client's registered subject type may
//     override Default (SubjectTypesPerClient), or every client is
//     pairwise (SubjectTypesPairwiseOnly).
//   - Derivation and Prefix apply whenever a client can be pairwise,
//     that is, when Default is pairwise or Dependencies.PairwiseSubjects
//     is set; otherwise they must be left zero. Derivation states
//     whether Dependencies.PairwiseSubjects can map a sub back to the
//     user (pairwise.Reversible, which requires a pairwise.Lookup) or
//     not (pairwise.OneWay). Prefix is put in front of every pairwise
//     sub, and may be empty, but must be built with pairwise.NewPrefix.
//
// PublicSubjects is the configuration that keeps every sub as it was.
// Changing Default, Enforcement or Prefix, or the deriver's key, changes
// the sub of every user at the affected clients for new grants: plan it
// as an identity migration, not a configuration change.
//
// Under pairwise.OneWay the server can't map a pairwise sub back to the
// end user, so its access tokens must keep the internal subject
// server-side: New refuses any Dependencies.AccessTokens but
// OpaqueAccessTokens. Under pairwise.Reversible any issuer works, and a
// resource server looks the sub up (resource.Config.PairwiseSubjects).
type SubjectConfig struct {
	Default     fapi.SubjectType
	Enforcement SubjectTypeEnforcement
	Derivation  pairwise.Derivation
	Prefix      pairwise.Prefix
}

// PublicSubjects returns the SubjectConfig in which every client's end
// users get the same, public sub, the server's behavior before
// Config.Subjects existed: a public Default, which clients may override
// per client.
func PublicSubjects() SubjectConfig {
	return SubjectConfig{Default: fapi.SubjectTypePublic, Enforcement: SubjectTypesPerClient}
}

// IsZero reports whether c is the zero SubjectConfig.
func (c SubjectConfig) IsZero() bool { return c == SubjectConfig{} }

// effectiveSubjects returns cfg.Subjects, reading an OAuthOnly server's
// zero value as PublicSubjects.
func effectiveSubjects(cfg Config) SubjectConfig {
	if cfg.OAuthOnly && cfg.Subjects.IsZero() {
		return PublicSubjects()
	}
	return cfg.Subjects
}

// pairwisePossible reports whether some client of a server configured
// with subjects and deriver could be pairwise.
func pairwisePossible(subjects SubjectConfig, deriver pairwise.Deriver) bool {
	return subjects.Default == fapi.SubjectTypePairwise || deriver != nil
}

// validateSubjects checks Config.Subjects against itself and
// Dependencies.PairwiseSubjects, and, when a client could be pairwise,
// derives (and for pairwise.Reversible looks up) a fixed input once, so
// a broken deriver fails New instead of an authorization.
func validateSubjects(cfg Config, deps Dependencies) error {
	subjects := effectiveSubjects(cfg)
	if err := validateSubjectTypes(subjects); err != nil {
		return err
	}
	if !pairwisePossible(subjects, deps.PairwiseSubjects) {
		if subjects.Derivation != 0 || subjects.Prefix.IsSet() || deps.PairwiseSubjectResolver != nil {
			return fmt.Errorf("server: config: subjects.derivation, subjects.prefix and dependencies.pairwise_subject_resolver apply only when a client can be pairwise (a pairwise default, or dependencies.pairwise_subjects set)")
		}
		return nil
	}
	if err := validatePairwiseSubjects(subjects, deps.PairwiseSubjects); err != nil {
		return err
	}
	if deps.PairwiseSubjectResolver != nil && subjects.Derivation != pairwise.OneWay {
		return fmt.Errorf("server: dependencies: pairwise_subject_resolver applies only to pairwise.OneWay subjects (pairwise.Reversible maps subs back through pairwise_subjects itself)")
	}
	if err := checkPairwiseAccessTokens(subjects, deps.AccessTokens, deps.PairwiseSubjectResolver); err != nil {
		return err
	}
	return probePairwiseSubjects(cfg.Issuer.String(), subjects, deps.PairwiseSubjects)
}

// checkPairwiseAccessTokens refuses, under pairwise.OneWay, an access
// token issuer other than OpaqueAccessTokens unless the embedder's own
// resolver (Dependencies.PairwiseSubjectResolver) maps subs back. A
// pairwise access token's "sub" is the pairwise one, and a one-way sub
// can't be mapped back to the end user, so without a resolver the
// internal subject a resource server authorizes by must stay in the
// server-side record OpaqueAccessTokens keeps; a self-contained token,
// readable by the client, must never carry it. Under pairwise.Reversible
// a resource server looks the sub up instead.
func checkPairwiseAccessTokens(subjects SubjectConfig, issuer AccessTokenIssuer, resolver pairwise.SubjectResolver) error {
	if subjects.Derivation != pairwise.OneWay || resolver != nil {
		return nil
	}
	switch issuer.(type) {
	case OpaqueAccessTokens, *OpaqueAccessTokens:
		return nil
	}
	return fmt.Errorf("server: dependencies: access_tokens must be OpaqueAccessTokens with pairwise.OneWay subjects: a one-way pairwise sub can't be mapped back to its end user, so the internal subject must stay in a server-side token record (use pairwise.Reversible, or set dependencies.pairwise_subject_resolver, for self-contained access tokens)")
}

// validateSubjectTypes checks Default and Enforcement.
func validateSubjectTypes(subjects SubjectConfig) error {
	switch {
	case subjects.Default == 0:
		return fmt.Errorf("server: config: subjects.default is required (PublicSubjects() keeps every sub as it is today)")
	case !subjects.Default.IsValid():
		return fmt.Errorf("server: config: subjects.default is invalid")
	case subjects.Enforcement == 0:
		return fmt.Errorf("server: config: subjects.enforcement is required (SubjectTypesPerClient or SubjectTypesPairwiseOnly)")
	case !subjects.Enforcement.IsValid():
		return fmt.Errorf("server: config: subjects.enforcement is invalid")
	case subjects.Enforcement == SubjectTypesPairwiseOnly && subjects.Default != fapi.SubjectTypePairwise:
		return fmt.Errorf("server: config: subjects.enforcement SubjectTypesPairwiseOnly requires a pairwise subjects.default")
	}
	return nil
}

// validatePairwiseSubjects checks the settings that apply once a client
// can be pairwise.
func validatePairwiseSubjects(subjects SubjectConfig, deriver pairwise.Deriver) error {
	switch {
	case deriver == nil:
		return fmt.Errorf("server: dependencies: pairwise_subjects is required with a pairwise subjects.default")
	case subjects.Derivation == 0:
		return fmt.Errorf("server: config: subjects.derivation is required when a client can be pairwise (pairwise.OneWay or pairwise.Reversible)")
	case !subjects.Derivation.IsValid():
		return fmt.Errorf("server: config: subjects.derivation is invalid")
	case !subjects.Prefix.IsSet():
		return fmt.Errorf("server: config: subjects.prefix is required when a client can be pairwise (pairwise.NewPrefix, which accepts \"\")")
	}
	if _, ok := deriver.(pairwise.Lookup); subjects.Derivation == pairwise.Reversible && !ok {
		return fmt.Errorf("server: config: subjects.derivation pairwise.Reversible requires dependencies.pairwise_subjects to implement pairwise.Lookup")
	}
	return nil
}

// Fixed input for probePairwiseSubjects.
const (
	pairwiseProbeSector  = "fapigo.pairwise.probe"
	pairwiseProbeSubject = "fapigo-pairwise-probe"
)

// probePairwiseSubjects derives a fixed input through deriver, checks
// the body, and for pairwise.Reversible looks it up again, under the
// same time bound as the signing-key check.
func probePairwiseSubjects(issuer string, subjects SubjectConfig, deriver pairwise.Deriver) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyCheckTimeout)
	defer cancel()
	in, err := pairwise.NewInput(issuer, pairwiseProbeSector, pairwiseProbeSubject)
	if err != nil {
		return fmt.Errorf("server: config: subjects: the issuer can't be a pairwise input: %w", err)
	}
	body, err := deriver.DerivePairwiseSubject(ctx, in)
	if err != nil {
		return fmt.Errorf("server: dependencies: pairwise_subjects can't derive a subject: %w", err)
	}
	if err := pairwise.CheckBody(body); err != nil {
		return fmt.Errorf("server: dependencies: pairwise_subjects derived an unusable subject: %w", err)
	}
	if subjects.Derivation != pairwise.Reversible {
		return nil
	}
	got, err := deriver.(pairwise.Lookup).LookupInternalSubject(ctx, issuer, pairwiseProbeSector, body)
	if err != nil || got != pairwiseProbeSubject {
		return fmt.Errorf("server: dependencies: pairwise_subjects can't look up the subject it derived: %v", lookupProblem(got, err))
	}
	return nil
}

// lookupProblem describes a failed probe lookup.
func lookupProblem(got string, err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("it returned %q", got)
}

// checkProductionPairwiseSubjects requires the deriver, when a client
// can be pairwise, to declare durable key custody: every instance and
// every restart must derive the same sub.
func checkProductionPairwiseSubjects(cfg Config, deps Dependencies, scaled bool) error {
	if !pairwisePossible(effectiveSubjects(cfg), deps.PairwiseSubjects) {
		return nil
	}
	if deps.PairwiseSubjectResolver != nil {
		if err := checkKeyCustody("pairwise_subject_resolver", deps.PairwiseSubjectResolver, scaled); err != nil {
			return err
		}
	}
	return checkKeyCustody("pairwise_subjects", deps.PairwiseSubjects, scaled)
}

// subjectTypesSupported returns Metadata's subject_types_supported.
func (s *Server) subjectTypesSupported() []string {
	types := supportedSubjectTypes(effectiveSubjects(s.cfg), s.deps.PairwiseSubjects)
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = t.String()
	}
	return out
}

// supportedSubjectTypes is the subject types a server configured with
// subjects and deriver gives clients: what discovery advertises, and
// what an automatically registered client may ask for.
func supportedSubjectTypes(subjects SubjectConfig, deriver pairwise.Deriver) []fapi.SubjectType {
	switch {
	case subjects.Enforcement == SubjectTypesPairwiseOnly:
		return []fapi.SubjectType{fapi.SubjectTypePairwise}
	case pairwisePossible(subjects, deriver):
		return []fapi.SubjectType{fapi.SubjectTypePublic, fapi.SubjectTypePairwise}
	default:
		return []fapi.SubjectType{fapi.SubjectTypePublic}
	}
}
