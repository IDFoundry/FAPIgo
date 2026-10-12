package resource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
)

const testPairwiseIssuer = "https://as.example.com"

// pairwiseResolver resolves every token as mTLS-bound to thumbprint,
// with subject, issuer and claims.
type pairwiseResolver struct {
	subject, issuer string
	claims          map[string]json.RawMessage
	thumbprint      string
	now             time.Time
}

func (r pairwiseResolver) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	return resource.ResolvedAccessToken{
		Subject: r.subject, Issuer: r.issuer, ClientID: "client-1", Key: "token-1", Claims: r.claims,
		SenderConstrain: storage.SenderConstrainMTLS, Thumbprint: r.thumbprint, ExpiresAt: r.now.Add(time.Minute),
	}, nil
}

// fakeLookup maps one body, under one issuer and sector, to "user-1".
type fakeLookup struct {
	issuer, sector, body string
	err                  error
}

func (l fakeLookup) LookupInternalSubject(_ context.Context, issuer, sector, body string) (string, error) {
	if l.err != nil {
		return "", l.err
	}
	if issuer != l.issuer || sector != l.sector || body != l.body {
		return "", pairwise.ErrSubjectNotFound
	}
	return "user-1", nil
}

func mustPrefix(t *testing.T, s string) pairwise.Prefix {
	t.Helper()
	p, err := pairwise.NewPrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func stringClaim(s string) json.RawMessage {
	raw, _ := json.Marshal(s)
	return raw
}

// TestVerifyResolvesPairwiseSubjects: Subject is the end user's
// internal subject and ClientSubject the sub the client was given —
// from a server-side record's client_sub, from a lookup of a
// self-contained token's pairwise sub, or both the token's sub when it's
// public — and every pairwise sub that can't be resolved fails closed.
func TestVerifyResolvesPairwiseSubjects(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	lookup := fakeLookup{issuer: testPairwiseIssuer, sector: "client.example", body: "abc"}
	sector := map[string]json.RawMessage{"pairwise_sector": stringClaim("client.example")}
	for name, tc := range map[string]struct {
		subject, issuer string
		claims          map[string]json.RawMessage
		lookup          pairwise.Lookup
		wantSubject     string
		wantClient      string
		wantErr         resource.ErrorCode
	}{
		"public": {subject: "user-1", wantSubject: "user-1", wantClient: "user-1"},
		"public, with a lookup": {subject: "user-1", lookup: lookup,
			wantSubject: "user-1", wantClient: "user-1"},
		"server-side record": {subject: "user-1", claims: map[string]json.RawMessage{"client_sub": stringClaim("pw:abc"), "pairwise_sector": stringClaim("client.example")},
			wantSubject: "user-1", wantClient: "pw:abc"},
		"record, malformed client_sub": {subject: "user-1", claims: map[string]json.RawMessage{"client_sub": json.RawMessage(`""`)},
			wantErr: resource.ErrorInvalidToken},
		"self-contained, looked up": {subject: "pw:abc", issuer: testPairwiseIssuer, claims: sector, lookup: lookup,
			wantSubject: "user-1", wantClient: "pw:abc"},
		"self-contained, no lookup": {subject: "pw:abc", issuer: testPairwiseIssuer, claims: sector,
			wantErr: resource.ErrorServerError},
		"self-contained, no issuer": {subject: "pw:abc", claims: sector, lookup: lookup,
			wantErr: resource.ErrorServerError},
		"another prefix": {subject: "xx:abc", issuer: testPairwiseIssuer, claims: sector, lookup: lookup,
			wantErr: resource.ErrorInvalidToken},
		"not a body": {subject: "pw:a b", issuer: testPairwiseIssuer, claims: sector, lookup: lookup,
			wantErr: resource.ErrorInvalidToken},
		"unknown body": {subject: "pw:abd", issuer: testPairwiseIssuer, claims: sector, lookup: lookup,
			wantErr: resource.ErrorInvalidToken},
		"another sector": {subject: "pw:abc", issuer: testPairwiseIssuer, claims: map[string]json.RawMessage{"pairwise_sector": stringClaim("other.example")}, lookup: lookup,
			wantErr: resource.ErrorInvalidToken},
		"malformed sector": {subject: "pw:abc", issuer: testPairwiseIssuer, claims: map[string]json.RawMessage{"pairwise_sector": json.RawMessage(`1`)}, lookup: lookup,
			wantErr: resource.ErrorInvalidToken},
		"lookup unavailable": {subject: "pw:abc", issuer: testPairwiseIssuer, claims: sector, lookup: fakeLookup{err: errors.New("store down")},
			wantErr: resource.ErrorServerError},
	} {
		t.Run(name, func(t *testing.T) {
			v := pairwiseVerifier(t, pairwiseResolver{subject: tc.subject, issuer: tc.issuer, claims: tc.claims, thumbprint: mtls.Thumbprint(cert), now: now}, tc.lookup, now)
			authz, err := v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
			checkSubjects(t, authz, err, tc.wantSubject, tc.wantClient, tc.wantErr)
		})
	}
}

// pairwiseVerifier is a verifier over resolver, looking pairwise subs up
// through lookup, under the prefix "pw:", when it isn't nil.
func pairwiseVerifier(t *testing.T, resolver resource.AccessTokenResolver, lookup pairwise.Lookup, now time.Time) *resource.Verifier {
	t.Helper()
	cfg := validConfig(t)
	deps := resource.Dependencies{
		AccessTokens: resolver,
		Replay:       &fakeReplayStore{},
		Revocation:   &fakeRevocationChecker{},
		Clock:        fixedClock{now: now},
	}
	if lookup != nil {
		deps.PairwiseSubjects = lookup
		cfg.PairwisePrefix = mustPrefix(t, "pw:")
	}
	v, err := resource.NewVerifier(cfg, deps)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// checkSubjects checks Verify's result: the error code wantErr, or the
// subjects wantSubject and wantClient.
func checkSubjects(t *testing.T, authz resource.AuthorizationContext, err error, wantSubject, wantClient string, wantErr resource.ErrorCode) {
	t.Helper()
	if wantErr != "" {
		var rerr *resource.Error
		if !errors.As(err, &rerr) || rerr.Code() != wantErr {
			t.Fatalf("Verify = %v, want %s", err, wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authz.Subject != wantSubject || authz.ClientSubject != wantClient {
		t.Fatalf("Subject, ClientSubject = %q, %q; want %q, %q", authz.Subject, authz.ClientSubject, wantSubject, wantClient)
	}
}

// TestNewVerifierPairsPairwiseSubjectsWithAPrefix: a pairwise lookup
// needs the server's prefix, and a prefix without a lookup is refused.
func TestNewVerifierPairsPairwiseSubjectsWithAPrefix(t *testing.T) {
	lookup := fakeLookup{}
	for name, tc := range map[string]struct {
		lookup pairwise.Lookup
		prefix bool
		ok     bool
	}{
		"neither":           {nil, false, true},
		"both":              {lookup, true, true},
		"lookup, no prefix": {lookup, false, false},
		"prefix, no lookup": {nil, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies(t)
			deps.PairwiseSubjects = tc.lookup
			if tc.prefix {
				cfg.PairwisePrefix = mustPrefix(t, "")
			}
			_, err := resource.NewVerifier(cfg, deps)
			if (err == nil) != tc.ok {
				t.Fatalf("NewVerifier = %v, want ok %v", err, tc.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "pairwise_prefix") {
				t.Fatalf("NewVerifier = %v, want a pairwise_prefix error", err)
			}
		})
	}
}

// custodyLookup is a fakeLookup declaring custody.
type custodyLookup struct {
	fakeLookup
	custody keys.KeyCustody
}

func (l custodyLookup) KeyCustody() keys.KeyCustody { return l.custody }

// TestProductionRequiresPairwiseLookupCustody: under production a
// pairwise lookup must be durable, and cross-instance consistent for a
// fleet, so every instance maps a sub to the same end user.
func TestProductionRequiresPairwiseLookupCustody(t *testing.T) {
	for name, tc := range map[string]struct {
		lookup     pairwise.Lookup
		deployment resource.Deployment
		want       string
	}{
		"undeclared":                 {fakeLookup{}, resource.DeploymentSingleInstance, "pairwise_subjects must implement keys.KeyCustodyAssurance"},
		"not durable":                {custodyLookup{}, resource.DeploymentSingleInstance, "pairwise_subjects must declare Durable"},
		"scaled, not cross-instance": {custodyLookup{custody: keys.KeyCustody{Durable: true}}, resource.DeploymentHorizontallyScaled, "pairwise_subjects must declare CrossInstanceConsistent"},
		"durable":                    {custodyLookup{custody: keys.KeyCustody{Durable: true}}, resource.DeploymentSingleInstance, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionSetup(t)
			cfg.Deployment = tc.deployment
			deps.PairwiseSubjects = tc.lookup
			cfg.PairwisePrefix = mustPrefix(t, "pw:")
			_, err := resource.NewVerifier(cfg, deps)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("NewVerifier = %v, want a verifier", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewVerifier = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// fakeResolver is an embedder's own mapping: it maps the whole sub
// "pw:abc", under one issuer and sector, to "user-1".
type fakeResolver struct {
	issuer, sector, sub string
	err                 error
}

func (r fakeResolver) ResolveSubject(_ context.Context, issuer, sector, sub string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if issuer != r.issuer || sector != r.sector || sub != r.sub {
		return "", pairwise.ErrSubjectNotFound
	}
	return "user-1", nil
}

// TestVerifyResolvesOneWayPairwiseSubjects: without a pairwise.Lookup, a
// self-contained token's pairwise sub is resolved through the embedder's
// SubjectResolver, failing closed for a sub it doesn't know or can't
// answer for; with both, the lookup is used.
func TestVerifyResolvesOneWayPairwiseSubjects(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	resolver := fakeResolver{issuer: testPairwiseIssuer, sector: "client.example", sub: "pw:abc"}
	sector := map[string]json.RawMessage{"pairwise_sector": stringClaim("client.example")}
	for name, tc := range map[string]struct {
		subject  string
		resolver pairwise.SubjectResolver
		lookup   pairwise.Lookup
		wantErr  resource.ErrorCode
	}{
		"resolved":                    {subject: "pw:abc", resolver: resolver},
		"unknown sub":                 {subject: "pw:abd", resolver: resolver, wantErr: resource.ErrorInvalidToken},
		"resolver unavailable":        {subject: "pw:abc", resolver: fakeResolver{err: errors.New("mapping down")}, wantErr: resource.ErrorServerError},
		"lookup preferred":            {subject: "pw:abc", resolver: fakeResolver{err: errors.New("never called")}, lookup: fakeLookup{issuer: testPairwiseIssuer, sector: "client.example", body: "abc"}},
		"neither lookup nor resolver": {subject: "pw:abc", wantErr: resource.ErrorServerError},
	} {
		t.Run(name, func(t *testing.T) {
			v := pairwiseVerifierWith(t, pairwiseResolver{subject: tc.subject, issuer: testPairwiseIssuer, claims: sector, thumbprint: mtls.Thumbprint(cert), now: now}, tc.lookup, tc.resolver, now)
			authz, err := v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
			checkSubjects(t, authz, err, "user-1", tc.subject, tc.wantErr)
		})
	}
}

// pairwiseVerifierWith is pairwiseVerifier, also given resolver.
func pairwiseVerifierWith(t *testing.T, accessTokens resource.AccessTokenResolver, lookup pairwise.Lookup, resolver pairwise.SubjectResolver, now time.Time) *resource.Verifier {
	t.Helper()
	cfg := validConfig(t)
	deps := resource.Dependencies{
		AccessTokens:    accessTokens,
		Replay:          &fakeReplayStore{},
		Revocation:      &fakeRevocationChecker{},
		Clock:           fixedClock{now: now},
		SubjectResolver: resolver,
	}
	if lookup != nil {
		deps.PairwiseSubjects = lookup
		cfg.PairwisePrefix = mustPrefix(t, "pw:")
	}
	v, err := resource.NewVerifier(cfg, deps)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// custodyResolver is a fakeResolver declaring custody.
type custodyResolver struct {
	fakeResolver
	custody keys.KeyCustody
}

func (r custodyResolver) KeyCustody() keys.KeyCustody { return r.custody }

// TestProductionRequiresSubjectResolverCustody: under production the
// embedder's resolver must be durable, and cross-instance consistent for
// a fleet.
func TestProductionRequiresSubjectResolverCustody(t *testing.T) {
	for name, tc := range map[string]struct {
		resolver   pairwise.SubjectResolver
		deployment resource.Deployment
		want       string
	}{
		"undeclared":                 {fakeResolver{}, resource.DeploymentSingleInstance, "subject_resolver must implement keys.KeyCustodyAssurance"},
		"not durable":                {custodyResolver{}, resource.DeploymentSingleInstance, "subject_resolver must declare Durable"},
		"scaled, not cross-instance": {custodyResolver{custody: keys.KeyCustody{Durable: true}}, resource.DeploymentHorizontallyScaled, "subject_resolver must declare CrossInstanceConsistent"},
		"durable":                    {custodyResolver{custody: keys.KeyCustody{Durable: true}}, resource.DeploymentSingleInstance, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionSetup(t)
			cfg.Deployment = tc.deployment
			deps.SubjectResolver = tc.resolver
			_, err := resource.NewVerifier(cfg, deps)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("NewVerifier = %v, want a verifier", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewVerifier = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
