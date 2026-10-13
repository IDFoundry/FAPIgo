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
	"github.com/idfoundry/fapigo/resource"
)

// TestVerifyPairwiseClientSubjectsOnly: a resource server outside the
// OpenID Provider accepts a pairwise sub without anything that maps it
// back, and never learns the internal subject, whether the token is
// self-contained or a server-side record that holds it; a public sub is
// reported as before.
func TestVerifyPairwiseClientSubjectsOnly(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	sector := map[string]json.RawMessage{"pairwise_sector": stringClaim("client.example")}
	for name, tc := range map[string]struct {
		subject, issuer string
		claims          map[string]json.RawMessage
		wantSubject     string
		wantClient      string
		wantErr         resource.ErrorCode
	}{
		"public": {subject: "user-1", wantSubject: "user-1", wantClient: "user-1"},
		"self-contained pairwise": {subject: "pw:abc", issuer: testPairwiseIssuer, claims: sector,
			wantSubject: "", wantClient: "pw:abc"},
		"self-contained, no issuer": {subject: "pw:abc", claims: sector,
			wantSubject: "", wantClient: "pw:abc"},
		"server-side record": {subject: "user-1", claims: map[string]json.RawMessage{"client_sub": stringClaim("pw:abc"), "pairwise_sector": stringClaim("client.example")},
			wantSubject: "", wantClient: "pw:abc"},
		"malformed sector": {subject: "pw:abc", issuer: testPairwiseIssuer, claims: map[string]json.RawMessage{"pairwise_sector": json.RawMessage(`1`)},
			wantErr: resource.ErrorInvalidToken},
		"malformed client_sub": {subject: "user-1", claims: map[string]json.RawMessage{"client_sub": json.RawMessage(`""`)},
			wantErr: resource.ErrorInvalidToken},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.PairwiseResolution = resource.PairwiseClientSubjectsOnly
			deps := resource.Dependencies{
				AccessTokens: pairwiseResolver{subject: tc.subject, issuer: tc.issuer, claims: tc.claims, thumbprint: mtls.Thumbprint(cert), now: now},
				Replay:       &fakeReplayStore{},
				Revocation:   &fakeRevocationChecker{},
				Clock:        fixedClock{now: now},
			}
			v, err := resource.NewVerifier(cfg, deps)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			authz, err := v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
			checkSubjects(t, authz, err, tc.wantSubject, tc.wantClient, tc.wantErr)
		})
	}
}

// TestNewVerifierRefusesClientSubjectsOnlyWithAMapping: a verifier
// either maps pairwise subs back or doesn't, and an unknown
// PairwiseResolution is refused.
func TestNewVerifierRefusesClientSubjectsOnlyWithAMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		resolution resource.PairwiseResolution
		configure  func(*resource.Config, *resource.Dependencies)
		want       string
	}{
		"with a lookup": {resource.PairwiseClientSubjectsOnly, func(c *resource.Config, d *resource.Dependencies) {
			d.PairwiseSubjects = fakeLookup{}
			c.PairwisePrefix = mustPrefix(t, "pw:")
		}, "can't be combined"},
		"with a resolver": {resource.PairwiseClientSubjectsOnly, func(_ *resource.Config, d *resource.Dependencies) {
			d.PairwiseSubjectResolver = fakeResolver{}
		}, "can't be combined"},
		"unknown": {resource.PairwiseResolution(9), func(*resource.Config, *resource.Dependencies) {}, "pairwise_resolution is invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies(t)
			cfg.PairwiseResolution = tc.resolution
			tc.configure(&cfg, &deps)
			_, err := resource.NewVerifier(cfg, deps)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewVerifier = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// TestVerifyNamesTheOptionsForAnUnmappablePairwiseSub: with nothing to
// map a pairwise sub back, Verify fails closed, and its error says what
// to configure on either side of the OP's boundary.
func TestVerifyNamesTheOptionsForAnUnmappablePairwiseSub(t *testing.T) {
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, _ := url.Parse("https://rs.example.com/accounts")
	v := pairwiseVerifier(t, pairwiseResolver{subject: "pw:abc", issuer: testPairwiseIssuer,
		claims: map[string]json.RawMessage{"pairwise_sector": stringClaim("client.example")}, thumbprint: mtls.Thumbprint(cert), now: now}, nil, now)
	_, err := v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorServerError {
		t.Fatalf("Verify = %v, want server_error", err)
	}
	for _, want := range []string{"pairwise_subjects", "pairwise_subject_resolver", "PairwiseClientSubjectsOnly"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q doesn't name %s", err, want)
		}
	}
}

// TestAuthorizationContextJSONOmitsInternalSubject: encoding an
// AuthorizationContext (for a debug response, say) never carries the
// internal subject.
func TestAuthorizationContextJSONOmitsInternalSubject(t *testing.T) {
	raw, err := json.Marshal(resource.AuthorizationContext{InternalSubject: "user-1", ClientSubject: "pw:abc"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "user-1") {
		t.Fatalf("JSON %s carries the internal subject", raw)
	}
}
