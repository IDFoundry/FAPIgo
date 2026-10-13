package server

import (
	"context"
	"fmt"
	"slices"

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
	// client can opt out. It requires a pairwise Default. A grant made
	// while its client got public subs is refused at its next use
	// (invalid_grant at refresh, at the code exchange and at the CIBA
	// token exchange), since a grant keeps the sub it was issued with:
	// switching to it ends those grants, and their clients authorize
	// again.
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
//   - Prefix applies whenever a client can be pairwise, that is, when
//     Default is pairwise or Dependencies.PairwiseSubjects is set;
//     otherwise it must be left zero. It is put in front of every
//     pairwise sub, and must be built with pairwise.NewPrefix. It may be
//     empty when the deriver is reversible, but not when it is one-way.
//     With pairwise.NewReversible, internal subjects are limited to
//     pairwise.MaxReversibleSubjectLength (151) bytes: a user with a
//     longer one can't complete an authorization at a pairwise client.
//
// Whether this server's pairwise subs can be mapped back to their users
// isn't configured: it is whether Dependencies.PairwiseSubjects
// implements pairwise.Lookup (pairwise.NewReversible,
// pairwise.NewReversibleWith and pairwise.NewMapping do; pairwise.NewHMAC
// doesn't, and is one-way), so the configuration can't claim more
// unlinkability than the deriver gives.
//
// PublicSubjects is the configuration that keeps every sub as it was.
// Changing Default, Enforcement or Prefix, or the deriver's key, changes
// the sub of every user at the affected clients for new grants: plan it
// as an identity migration, not a configuration change.
//
// With a one-way deriver the server can't map a pairwise sub back to the
// end user, so its access tokens must keep the internal subject
// server-side: New refuses any Dependencies.AccessTokens but
// OpaqueAccessTokens, unless Dependencies.PairwiseSubjectResolver maps
// subs back. With a reversible deriver any issuer works, and a resource
// server looks the sub up.
type SubjectConfig struct {
	Default     fapi.SubjectType
	Enforcement SubjectTypeEnforcement
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

// reversibleDeriver reports whether deriver can map a body back to its
// internal subject: whether it implements pairwise.Lookup.
func reversibleDeriver(deriver pairwise.Deriver) bool {
	_, ok := deriver.(pairwise.Lookup)
	return ok
}

// pairwisePossible reports whether some client of a server configured
// with subjects and deriver could be pairwise.
func pairwisePossible(subjects SubjectConfig, deriver pairwise.Deriver) bool {
	return subjects.Default == fapi.SubjectTypePairwise || deriver != nil
}

// validateSubjects checks Config.Subjects against itself and
// Dependencies.PairwiseSubjects, and, when a client could be pairwise,
// derives (and for a reversible deriver looks up) a fixed input once, so
// a broken deriver fails New instead of an authorization.
func validateSubjects(cfg Config, deps Dependencies) error {
	subjects := effectiveSubjects(cfg)
	if err := validateSubjectTypes(subjects); err != nil {
		return err
	}
	if _, _, err := automaticRegistrationSubjects(cfg, deps.PairwiseSubjects); err != nil {
		return err
	}
	if !pairwisePossible(subjects, deps.PairwiseSubjects) {
		if subjects.Prefix.IsSet() || deps.PairwiseSubjectResolver != nil {
			return fmt.Errorf("server: config: subjects.prefix and dependencies.pairwise_subject_resolver apply only when a client can be pairwise (a pairwise default, or dependencies.pairwise_subjects set)")
		}
		return nil
	}
	if err := validatePairwiseSubjects(subjects, deps.PairwiseSubjects, deps.PairwiseSubjectResolver); err != nil {
		return err
	}
	if deps.PairwiseSubjectResolver != nil && reversibleDeriver(deps.PairwiseSubjects) {
		return fmt.Errorf("server: dependencies: pairwise_subject_resolver applies only to a one-way pairwise_subjects (one that doesn't implement pairwise.Lookup); %T maps subs back itself", deps.PairwiseSubjects)
	}
	if err := checkPairwiseAccessTokens(deps.PairwiseSubjects, deps.AccessTokens, deps.PairwiseSubjectResolver); err != nil {
		return err
	}
	return probePairwiseSubjects(cfg.Issuer.String(), deps.PairwiseSubjects)
}

// checkPairwiseAccessTokens refuses, with a one-way deriver, an access
// token issuer other than OpaqueAccessTokens unless the embedder's own
// resolver (Dependencies.PairwiseSubjectResolver) maps subs back. A
// pairwise access token's "sub" is the pairwise one, and a one-way sub
// can't be mapped back to the end user, so without a resolver the
// internal subject a resource server authorizes by must stay in the
// server-side record OpaqueAccessTokens keeps; a self-contained token,
// readable by the client, must never carry it. With a reversible
// deriver a resource server looks the sub up instead.
func checkPairwiseAccessTokens(deriver pairwise.Deriver, issuer AccessTokenIssuer, resolver pairwise.SubjectResolver) error {
	if reversibleDeriver(deriver) || resolver != nil {
		return nil
	}
	switch issuer.(type) {
	case OpaqueAccessTokens, *OpaqueAccessTokens:
		return nil
	}
	return fmt.Errorf("server: dependencies: access_tokens must be OpaqueAccessTokens with a one-way pairwise_subjects (%T): a one-way pairwise sub can't be mapped back to its end user, so the internal subject must stay in a server-side token record (use a reversible deriver, pairwise.NewReversible or pairwise.NewMapping, or set dependencies.pairwise_subject_resolver, for self-contained access tokens)", deriver)
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
// can be pairwise. An empty Prefix is refused for a one-way deriver with
// no resolver: nothing could then tell a pairwise sub from a public one,
// and the server's own checks (a signed UserInfo response's sub, say)
// couldn't catch the internal subject passed where the pairwise one
// belongs.
func validatePairwiseSubjects(subjects SubjectConfig, deriver pairwise.Deriver, resolver pairwise.SubjectResolver) error {
	switch {
	case deriver == nil:
		return fmt.Errorf("server: dependencies: pairwise_subjects is required with a pairwise subjects.default (pairwise.NewReversible, pairwise.NewReversibleWith, pairwise.NewMapping or pairwise.NewHMAC)")
	case !subjects.Prefix.IsSet():
		return fmt.Errorf("server: config: subjects.prefix is required when a client can be pairwise (pairwise.NewPrefix, which accepts \"\" for a reversible deriver)")
	case subjects.Prefix.String() == "" && !reversibleDeriver(deriver) && resolver == nil:
		return fmt.Errorf("server: config: subjects.prefix must not be empty with a one-way pairwise_subjects (%T): set one, such as pairwise.NewPrefix(\"ppid:\"), so a pairwise sub can't be mistaken for an internal subject", deriver)
	}
	return nil
}

// Fixed input for probePairwiseSubjects.
const (
	pairwiseProbeSector  = "fapigo.pairwise.probe"
	pairwiseProbeSubject = "fapigo-pairwise-probe"
)

// probePairwiseSubjects derives a fixed input through deriver, checks
// the body, and for a reversible deriver looks it up again, under the
// same time bound as the signing-key check.
func probePairwiseSubjects(issuer string, deriver pairwise.Deriver) error {
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
	lookup, ok := deriver.(pairwise.Lookup)
	if !ok {
		return nil
	}
	got, err := lookup.LookupInternalSubject(ctx, issuer, pairwiseProbeSector, body)
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
	return subjectTypeNames(supportedSubjectTypes(effectiveSubjects(s.cfg), s.deps.PairwiseSubjects))
}

// subjectTypeNames is types' wire names.
func subjectTypeNames(types []fapi.SubjectType) []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = t.String()
	}
	return out
}

// AutomaticRegistrationSubjectTypes is the subject_types_supported to
// advertise to automatically registered Relying Parties, in the
// openid_provider metadata of this server's Entity Configuration: what
// they may ask for, Config.AutomaticRegistration.SubjectTypes when set,
// otherwise everything the server issues (as Metadata advertises).
func (s *Server) AutomaticRegistrationSubjectTypes() []string {
	types, _, _ := automaticRegistrationSubjects(s.cfg, s.deps.PairwiseSubjects)
	return subjectTypeNames(types)
}

// automaticRegistrationSubjects is the subject types automatically
// registered clients are offered, and the one an RP naming none gets:
// Config.AutomaticRegistration.SubjectTypes, which must be a subset of
// what the server issues, or everything it issues; the default is
// Config.Subjects.Default when offered, otherwise the subset's only type
// (a subset of the at most two types a server issues that leaves out the
// default has exactly one entry).
func automaticRegistrationSubjects(cfg Config, deriver pairwise.Deriver) ([]fapi.SubjectType, fapi.SubjectType, error) {
	subjects := effectiveSubjects(cfg)
	issued := supportedSubjectTypes(subjects, deriver)
	offered := cfg.AutomaticRegistration.SubjectTypes
	if len(offered) == 0 {
		return issued, subjects.Default, nil
	}
	for i, t := range offered {
		switch {
		case !t.IsValid():
			return nil, 0, fmt.Errorf("server: config: automatic_registration.subject_types[%d] is not a valid subject type", i)
		case !slices.Contains(issued, t):
			return nil, 0, fmt.Errorf("server: config: automatic_registration.subject_types[%d] is %s, which config.subjects doesn't issue", i, t)
		case slices.Contains(offered[:i], t):
			return nil, 0, fmt.Errorf("server: config: automatic_registration.subject_types repeats %s", t)
		}
	}
	if slices.Contains(offered, subjects.Default) {
		return offered, subjects.Default, nil
	}
	return offered, offered[0], nil
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
