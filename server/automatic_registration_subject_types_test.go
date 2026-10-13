package server_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// legacyClientID is a statically registered client that keeps public
// subs while automatically registered ones are offered only pairwise.
const legacyClientID fapi.ClientID = "legacy-rp"

// narrowedAutomaticRegistrationServer is a server issuing public and
// pairwise subs (pairwise by default, per client), with a statically
// registered legacy client on public subs and automatic registration
// offering only offered, and the reason any automatic registration
// failed.
func narrowedAutomaticRegistrationServer(t *testing.T, f *automaticRegistrationFixture, offered []fapi.SubjectType) (*server.Server, *error) {
	t.Helper()
	failure := new(error)
	cfg, deps := automaticRegistrationTestConfig(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.Subjects = fedPairwiseSubjects(t, fapi.SubjectTypePairwise, server.SubjectTypesPerClient)
		cfg.AutomaticRegistration.SubjectTypes = offered
		cfg.AutomaticRegistration.OnResolutionFailure = func(_ context.Context, _ fapi.ClientID, err error) { *failure = err }
		deps.PairwiseSubjects = hmacDeriver(t)
		deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
		legacy, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                       legacyClientID,
			RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
			ClientAssertionAlgorithm: fapi.ES256,
			RequestObjectAlgorithm:   fapi.ES256,
			AllowedScopes:            []string{"openid"},
			SubjectType:              fapi.SubjectTypePublic,
		})
		if err != nil {
			t.Fatalf("NewRegisteredClient: %v", err)
		}
		deps.Clients.(*fakeClientRepository).clients[legacyClientID] = legacy
	})
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, failure
}

// TestAutomaticRegistrationSubjectTypesNarrowFederationRPs: with
// AutomaticRegistration.SubjectTypes set to pairwise alone, or left
// unset under a pairwise default, a Relying Party registering through
// federation gets pairwise subs whether it asks for them or names none,
// and one asking for public is refused, while a statically registered
// legacy client keeps its public subs.
func TestAutomaticRegistrationSubjectTypesNarrowFederationRPs(t *testing.T) {
	for name, offered := range map[string][]fapi.SubjectType{
		"pairwise offered": {fapi.SubjectTypePairwise},
		"unset":            nil,
	} {
		t.Run(name, func(t *testing.T) { checkFederationRPsGetPairwiseOnly(t, offered) })
	}
}

// checkFederationRPsGetPairwiseOnly is
// TestAutomaticRegistrationSubjectTypesNarrowFederationRPs for one
// AutomaticRegistration.SubjectTypes.
func checkFederationRPsGetPairwiseOnly(t *testing.T, offered []fapi.SubjectType) {
	const user = "user-1"
	authenticated := mustAuthenticated(t, user)
	for name, tc := range map[string]struct {
		subjectType string
		wantRefusal string
	}{
		"pairwise asked": {"pairwise", ""},
		"none asked":     {"", ""},
		"public asked":   {"public", "subject_type public is not one this OP issues"},
	} {
		t.Run(name, func(t *testing.T) {
			var extra []map[string]any
			if tc.subjectType != "" {
				extra = append(extra, map[string]any{"subject_type": tc.subjectType})
			}
			f := setupAutomaticRegistrationFixture(t, "", extra...)
			srv, failure := narrowedAutomaticRegistrationServer(t, f, offered)

			sub, err := srv.ClientSubject(context.Background(), fapi.ClientID(f.rpID), authenticated)
			if tc.wantRefusal != "" {
				checkAutomaticRegistrationRefused(t, sub, err, *failure, tc.wantRefusal)
			} else {
				checkAutomaticRegistrationSubject(t, sub, err, *failure, user, false)
			}

			legacySub, err := srv.ClientSubject(context.Background(), legacyClientID, authenticated)
			if err != nil || legacySub != user {
				t.Errorf("legacy client's sub = %q, %v; want its public sub %q", legacySub, err, user)
			}
		})
	}
}

// TestAutomaticRegistrationSubjectTypesAdvertised: discovery advertises
// what the server issues to any client, and
// AutomaticRegistrationSubjectTypes what federation RPs are offered.
func TestAutomaticRegistrationSubjectTypesAdvertised(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, "")
	for name, tc := range map[string]struct {
		offered        []fapi.SubjectType
		wantDiscovery  []string
		wantFederation []string
	}{
		"narrowed": {[]fapi.SubjectType{fapi.SubjectTypePairwise}, []string{"public", "pairwise"}, []string{"pairwise"}},
		// A pairwise default isn't something a federation RP can opt
		// out of unless public is listed.
		"unset":   {nil, []string{"public", "pairwise"}, []string{"pairwise"}},
		"widened": {[]fapi.SubjectType{fapi.SubjectTypePublic, fapi.SubjectTypePairwise}, []string{"public", "pairwise"}, []string{"public", "pairwise"}},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := narrowedAutomaticRegistrationServer(t, f, tc.offered)
			if got := srv.Metadata(context.Background()).SubjectTypesSupported; !slices.Equal(got, tc.wantDiscovery) {
				t.Errorf("Metadata subject_types_supported = %q, want %q", got, tc.wantDiscovery)
			}
			if got := srv.AutomaticRegistrationSubjectTypes(); !slices.Equal(got, tc.wantFederation) {
				t.Errorf("AutomaticRegistrationSubjectTypes = %q, want %q", got, tc.wantFederation)
			}
		})
	}
}

// TestAutomaticRegistrationSubjectTypesDefaultsToTheOnlyOffered: when
// the server's default isn't offered to federation RPs, an RP naming no
// subject_type gets the one type that is.
func TestAutomaticRegistrationSubjectTypesDefaultsToTheOnlyOffered(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, "")
	failure := new(error)
	cfg, deps := automaticRegistrationTestConfig(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		// Public by default, with pairwise clients possible.
		cfg.Subjects = fedPairwiseSubjects(t, fapi.SubjectTypePublic, server.SubjectTypesPerClient)
		cfg.AutomaticRegistration.SubjectTypes = []fapi.SubjectType{fapi.SubjectTypePairwise}
		cfg.AutomaticRegistration.OnResolutionFailure = func(_ context.Context, _ fapi.ClientID, err error) { *failure = err }
		deps.PairwiseSubjects = hmacDeriver(t)
		deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
	})
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sub, err := srv.ClientSubject(context.Background(), fapi.ClientID(f.rpID), mustAuthenticated(t, "user-1"))
	checkAutomaticRegistrationSubject(t, sub, err, *failure, "user-1", false)
}

// TestNewRefusesInvalidAutomaticRegistrationSubjectTypes: New refuses
// automatic registration subject types the server doesn't issue, a
// repeated one, or an invalid one.
func TestNewRefusesInvalidAutomaticRegistrationSubjectTypes(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, "")
	for name, tc := range map[string]struct {
		pairwiseServer bool
		offered        []fapi.SubjectType
		want           string
	}{
		"pairwise from a public-only server": {false, []fapi.SubjectType{fapi.SubjectTypePairwise}, "doesn't issue"},
		"public under pairwise only":         {true, []fapi.SubjectType{fapi.SubjectTypePublic}, "doesn't issue"},
		"repeated":                           {true, []fapi.SubjectType{fapi.SubjectTypePairwise, fapi.SubjectTypePairwise}, "repeats"},
		"invalid":                            {true, []fapi.SubjectType{99}, "not a valid subject type"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := automaticRegistrationTestConfig(t, f, func(cfg *server.Config, deps *server.Dependencies) {
				cfg.AutomaticRegistration.SubjectTypes = tc.offered
				if tc.pairwiseServer {
					cfg.Subjects = fedPairwiseSubjects(t, fapi.SubjectTypePairwise, server.SubjectTypesPairwiseOnly)
					deps.PairwiseSubjects = hmacDeriver(t)
					deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
				}
			})
			if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
