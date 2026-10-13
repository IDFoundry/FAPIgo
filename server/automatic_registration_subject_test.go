package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// pairwiseAutomaticRegistrationServer is newAutomaticRegistrationTestServer
// under subjects, with pairwise subjects derived by NewHMAC and opaque
// access tokens, and the reason any automatic registration failed.
func pairwiseAutomaticRegistrationServer(t *testing.T, f *automaticRegistrationFixture, subjects server.SubjectConfig) (*server.Server, *error) {
	t.Helper()
	failure := new(error)
	cfg, deps := automaticRegistrationTestConfig(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.Subjects = subjects
		deps.PairwiseSubjects = hmacDeriver(t)
		// One-way pairwise subjects need opaque access tokens, which keep
		// the internal subject in a server-side record.
		deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
		cfg.AutomaticRegistration.OnResolutionFailure = func(_ context.Context, _ fapi.ClientID, err error) { *failure = err }
	})
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, failure
}

func fedPairwiseSubjects(t *testing.T, def fapi.SubjectType, enforcement server.SubjectTypeEnforcement) server.SubjectConfig {
	t.Helper()
	return server.SubjectConfig{
		Default: def, Enforcement: enforcement,
		Derivation: pairwise.OneWay, Prefix: mustPrefix(t, testPairwisePrefix),
	}
}

// TestNewWiresSubjectTypesIntoAutomaticRegistration: server.New passes
// its subject types to automatic registration, so a Relying Party gets
// the subject_type its metadata asks for, or the server's default,
// and one the server doesn't issue isn't registered at all.
func TestNewWiresSubjectTypesIntoAutomaticRegistration(t *testing.T) {
	const user = "user-1"
	subject, err := server.NewSubjectID(user)
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	tests := []struct {
		name        string
		subjectType string // the RP's metadata; "" for none
		subjects    func(t *testing.T) server.SubjectConfig
		wantPublic  bool
		wantRefusal string
	}{
		{"pairwise asked", "pairwise", func(t *testing.T) server.SubjectConfig {
			return fedPairwiseSubjects(t, fapi.SubjectTypePublic, server.SubjectTypesPerClient)
		}, false, ""},
		{"none asked, public default", "", func(t *testing.T) server.SubjectConfig {
			return fedPairwiseSubjects(t, fapi.SubjectTypePublic, server.SubjectTypesPerClient)
		}, true, ""},
		{"none asked, pairwise default", "", func(t *testing.T) server.SubjectConfig {
			return fedPairwiseSubjects(t, fapi.SubjectTypePairwise, server.SubjectTypesPerClient)
		}, false, ""},
		{"public asked, pairwise only", "public", func(t *testing.T) server.SubjectConfig {
			return fedPairwiseSubjects(t, fapi.SubjectTypePairwise, server.SubjectTypesPairwiseOnly)
		}, false, "subject_type public is not one this OP issues"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var extra []map[string]any
			if tc.subjectType != "" {
				extra = append(extra, map[string]any{"subject_type": tc.subjectType})
			}
			f := setupAutomaticRegistrationFixture(t, "", extra...)
			srv, failure := pairwiseAutomaticRegistrationServer(t, f, tc.subjects(t))
			sub, err := srv.ClientSubject(context.Background(), fapi.ClientID(f.rpID), authenticated)
			if tc.wantRefusal != "" {
				checkAutomaticRegistrationRefused(t, sub, err, *failure, tc.wantRefusal)
				return
			}
			checkAutomaticRegistrationSubject(t, sub, err, *failure, user, tc.wantPublic)
		})
	}
}

// checkAutomaticRegistrationRefused checks the client wasn't registered,
// for the reason want.
func checkAutomaticRegistrationRefused(t *testing.T, sub string, err, failure error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("ClientSubject = %q, want the client refused", sub)
	}
	if failure == nil || !strings.Contains(failure.Error(), want) {
		t.Fatalf("registration failure = %v, want %q", failure, want)
	}
}

// checkAutomaticRegistrationSubject checks sub is user's public sub, or a
// pairwise one.
func checkAutomaticRegistrationSubject(t *testing.T, sub string, err, failure error, user string, wantPublic bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("ClientSubject: %v (registration failure: %v)", err, failure)
	}
	if public := sub == user; public != wantPublic {
		t.Errorf("ClientSubject = %q, want public %v", sub, wantPublic)
	}
	if !wantPublic && !strings.HasPrefix(sub, testPairwisePrefix) {
		t.Errorf("ClientSubject = %q, want a pairwise sub with prefix %q", sub, testPairwisePrefix)
	}
}

// TestPublicServerRefusesAutomaticRegistrationAskingPairwise: a server
// issuing only public subjects doesn't register a Relying Party asking
// for pairwise ones, rather than giving it public subs it didn't ask
// for; the RP only sees invalid_client.
func TestPublicServerRefusesAutomaticRegistrationAskingPairwise(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, "", map[string]any{"subject_type": "pairwise"})
	var failure error
	srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, _ *server.Dependencies) {
		cfg.AutomaticRegistration.OnResolutionFailure = func(_ context.Context, _ fapi.ClientID, err error) { failure = err }
	})
	_, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, automaticRegistrationAssertion(t, f), nil)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
	if failure == nil || !strings.Contains(failure.Error(), "subject_type pairwise is not one this OP issues") {
		t.Errorf("registration failure = %v, want the subject_type refused", failure)
	}
}

// TestMetadataAdvertisesAutomaticRegistrationSubjectTypes: what
// discovery advertises is what automatic registration accepts.
func TestMetadataAdvertisesAutomaticRegistrationSubjectTypes(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)
	srv, _ := pairwiseAutomaticRegistrationServer(t, f, fedPairwiseSubjects(t, fapi.SubjectTypePairwise, server.SubjectTypesPairwiseOnly))
	md := srv.Metadata(context.Background())
	if got := strings.Join(md.SubjectTypesSupported, " "); got != "pairwise" {
		t.Errorf("subject_types_supported = %q, want pairwise", got)
	}
}

// automaticRegistrationAssertion is a private_key_jwt client assertion
// from f's RP.
func automaticRegistrationAssertion(t *testing.T, f *automaticRegistrationFixture) string {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: f.rpOIDCKey, Algorithm: fapi.ES256, KeyID: "rp-oidc",
		ClientID: f.rpID, Audience: testIssuer,
		Now: f.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}
