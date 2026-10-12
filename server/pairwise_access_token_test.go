package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// pairwiseResourceVerifier is a resource server for h's access tokens:
// JWT, or the opaque records of h's OpaqueAccessTokens, looking pairwise
// subs up through lookup when it isn't nil.
func pairwiseResourceVerifier(t *testing.T, h harness, lookup pairwise.Lookup) *resource.Verifier {
	t.Helper()
	var resolver resource.AccessTokenResolver
	if opaque, ok := h.deps.AccessTokens.(server.OpaqueAccessTokens); ok {
		resolver = resource.OpaqueAccessTokens{Store: opaque.Store}
	} else {
		issuerKeys, err := keys.NewLocalIssuerKeys(h.cfg.Issuer, h.deps.Keys)
		if err != nil {
			t.Fatal(err)
		}
		jwt, err := resource.NewJWTAccessTokens(issuerKeys, h.cfg.Issuer, testIssuer, fapi.ES256, 10*time.Minute, 4)
		if err != nil {
			t.Fatal(err)
		}
		resolver = jwt
	}
	cfg := resource.Config{
		Limits:    resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
		Assurance: resource.AssuranceDevelopment,
	}
	deps := resource.Dependencies{
		AccessTokens: resolver,
		Replay:       memstore.NewReplayStore(),
		Revocation:   resource.NoRevocation{},
		Clock:        fixedClock{now: h.now},
	}
	if lookup != nil {
		deps.PairwiseSubjects = lookup
		cfg.PairwisePrefix = mustPrefix(t, testPairwisePrefix)
	}
	verifier, err := resource.NewVerifier(cfg, deps)
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	return verifier
}

// verifyAuthorization presents accessToken, DPoP-bound to key, to
// verifier.
func verifyAuthorization(t *testing.T, verifier *resource.Verifier, key *ecdsa.PrivateKey, accessToken string, now time.Time) (resource.AuthorizationContext, error) {
	t.Helper()
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "GET", URL: target,
		AccessToken: accessToken, Now: now, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}
	return verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: target, Authorization: "DPoP " + accessToken, DPoPProofs: []string{proof},
	})
}

// jwtPayload is the decoded payload of the JWT raw.
func jwtPayload(t *testing.T, raw string) (map[string]json.RawMessage, string) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("access token isn't a JWT: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims, string(payload)
}

func stringClaimOf(t *testing.T, claims map[string]json.RawMessage, name string) string {
	t.Helper()
	var s string
	if raw, ok := claims[name]; ok {
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("claim %q: %v", name, err)
		}
	}
	return s
}

// assertOpaqueRecordSubjects checks the server-side record of the opaque
// access token raw: the internal subject as its own, the client's sub
// and its sector among its claims.
func assertOpaqueRecordSubjects(t *testing.T, store *memstore.AccessTokenStore, raw, internal, clientSub, sector string) {
	t.Helper()
	record, err := store.LookupAccessToken(context.Background(), storage.AccessTokenLookup{TokenHash: sha256.Sum256([]byte(raw))})
	if err != nil {
		t.Fatalf("LookupAccessToken: %v", err)
	}
	if record.Subject != internal || stringClaimOf(t, record.Claims, "client_sub") != clientSub || stringClaimOf(t, record.Claims, "pairwise_sector") != sector {
		t.Errorf("record sub, client_sub, pairwise_sector = %q, %q, %q; want %q, %q, %q",
			record.Subject, stringClaimOf(t, record.Claims, "client_sub"), stringClaimOf(t, record.Claims, "pairwise_sector"), internal, clientSub, sector)
	}
}

func mappingPairwise(t *testing.T) pairwise.Deriver {
	t.Helper()
	d, err := pairwise.NewMapping(memstore.NewPairwiseSubjectStore())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func reversiblePairwise(t *testing.T) pairwise.Deriver {
	t.Helper()
	d, err := pairwise.NewReversible(bytes.Repeat([]byte{1, 2}, 16), bytes.Repeat([]byte{3, 4}, 16))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestPairwiseJWTAccessTokens: under pairwise.Reversible (both the
// mapping and the encrypting deriver) a JWT access token's sub is the
// client's pairwise sub, with the sector it was derived for, and never
// the internal subject; a resource server looks it up to the internal
// subject, and fails closed without a lookup. A refresh issues the same.
func TestPairwiseJWTAccessTokens(t *testing.T) {
	for name, deriver := range map[string]func(*testing.T) pairwise.Deriver{
		"mapping":    mappingPairwise,
		"reversible": reversiblePairwise,
	} {
		t.Run(name, func(t *testing.T) { testPairwiseJWTAccessTokens(t, deriver(t)) })
	}
}

func testPairwiseJWTAccessTokens(t *testing.T, deriver pairwise.Deriver) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.Reversible, deriver)
	want := clientSubjectOf(t, h, "user-1")

	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	lookup, _ := deriver.(pairwise.Lookup)
	for name, accessToken := range map[string]string{"exchange": first.AccessToken.Reveal(), "refresh": refreshed.AccessToken.Reveal()} {
		t.Run(name, func(t *testing.T) {
			assertPairwiseJWTClaims(t, accessToken, want)
			assertResolvesTo(t, pairwiseResourceVerifier(t, h, lookup), dpopKey, accessToken, h.now, want)
			_, err := verifyAuthorization(t, pairwiseResourceVerifier(t, h, nil), dpopKey, accessToken, h.now)
			var rerr *resource.Error
			if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorServerError {
				t.Errorf("Verify without a lookup = %v, want server_error", err)
			}
		})
	}
}

// assertPairwiseJWTClaims checks a pairwise JWT access token: its sub is
// the client's want, it carries the sector it was derived for, and
// nothing in it is the internal subject.
func assertPairwiseJWTClaims(t *testing.T, accessToken, want string) {
	t.Helper()
	claims, payload := jwtPayload(t, accessToken)
	if got := stringClaimOf(t, claims, "sub"); got != want {
		t.Errorf("access token sub = %q, want %q", got, want)
	}
	if got := stringClaimOf(t, claims, "pairwise_sector"); got != "rp.example" {
		t.Errorf("access token pairwise_sector = %q, want rp.example", got)
	}
	if strings.Contains(payload, "user-1") || claims["client_sub"] != nil {
		t.Errorf("access token payload %s carries the internal subject", payload)
	}
}

// assertResolvesTo checks verifier gives accessToken the internal
// subject user-1 and the client subject want.
func assertResolvesTo(t *testing.T, verifier *resource.Verifier, key *ecdsa.PrivateKey, accessToken string, now time.Time, want string) {
	t.Helper()
	authz, err := verifyAuthorization(t, verifier, key, accessToken, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authz.Subject != "user-1" || authz.ClientSubject != want {
		t.Errorf("Subject, ClientSubject = %q, %q; want user-1, %q", authz.Subject, authz.ClientSubject, want)
	}
}

// TestPairwiseOpaqueAccessTokens: under pairwise.OneWay the access token
// is a server-side record keeping the internal subject, with the
// client's pairwise sub beside it, and a resource server gets both
// without a lookup. A refresh issues the same.
func TestPairwiseOpaqueAccessTokens(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, hmacDeriver(t))
	store, ok := h.deps.AccessTokens.(server.OpaqueAccessTokens).Store.(*memstore.AccessTokenStore)
	if !ok {
		t.Fatal("the one-way harness's access tokens aren't a memstore OpaqueAccessTokens")
	}
	want := clientSubjectOf(t, h, "user-1")

	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	for name, accessToken := range map[string]string{"exchange": first.AccessToken.Reveal(), "refresh": refreshed.AccessToken.Reveal()} {
		t.Run(name, func(t *testing.T) {
			assertOpaqueRecordSubjects(t, store, accessToken, "user-1", want, "rp.example")
			assertResolvesTo(t, pairwiseResourceVerifier(t, h, nil), dpopKey, accessToken, h.now, want)
		})
	}
}

// TestPublicAccessTokenClientSubject: a public client's access token
// gives the same sub as Subject and ClientSubject, and carries no
// pairwise claims.
func TestPublicAccessTokenClientSubject(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	claims, _ := jwtPayload(t, first.AccessToken.Reveal())
	if claims["pairwise_sector"] != nil || claims["client_sub"] != nil {
		t.Errorf("public access token carries pairwise claims: %v", claims)
	}
	authz, err := verifyAuthorization(t, pairwiseResourceVerifier(t, h, nil), dpopKey, first.AccessToken.Reveal(), h.now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authz.Subject != "user-1" || authz.ClientSubject != "user-1" {
		t.Errorf("Subject, ClientSubject = %q, %q; want user-1 for both", authz.Subject, authz.ClientSubject)
	}
}

// TestPairwiseOneWayJWTAccessTokensWithAResolver: under pairwise.OneWay a
// declared resolver lets JWT access tokens carry the pairwise sub, which
// a resource server maps back through the embedder's own mapping — and
// can't without it.
func TestPairwiseOneWayJWTAccessTokensWithAResolver(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	register(t, h, pairwiseClient(false))
	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePublic, Enforcement: server.SubjectTypesPerClient,
		Derivation: pairwise.OneWay, Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = hmacDeriver(t)
	resolver := subResolver{subjects: map[[3]string]string{}}
	h.deps.PairwiseSubjectResolver = resolver
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	want := clientSubjectOf(t, h, "user-1")
	// The embedder records the subs its clients are given.
	resolver.subjects[[3]string{testIssuer, "rp.example", want}] = "user-1"

	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	for name, accessToken := range map[string]string{"exchange": first.AccessToken.Reveal(), "refresh": refreshed.AccessToken.Reveal()} {
		t.Run(name, func(t *testing.T) {
			assertPairwiseJWTClaims(t, accessToken, want)
			assertResolvesTo(t, resolverResourceVerifier(t, h, resolver), dpopKey, accessToken, h.now, want)
			_, err := verifyAuthorization(t, pairwiseResourceVerifier(t, h, nil), dpopKey, accessToken, h.now)
			var rerr *resource.Error
			if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorServerError {
				t.Errorf("Verify without a resolver = %v, want server_error", err)
			}
		})
	}
}

// resolverResourceVerifier is a resource server for h's JWT access
// tokens, resolving pairwise subs through resolver.
func resolverResourceVerifier(t *testing.T, h harness, resolver pairwise.SubjectResolver) *resource.Verifier {
	t.Helper()
	issuerKeys, err := keys.NewLocalIssuerKeys(h.cfg.Issuer, h.deps.Keys)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := resource.NewJWTAccessTokens(issuerKeys, h.cfg.Issuer, testIssuer, fapi.ES256, 10*time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := resource.NewVerifier(resource.Config{
		Limits:    resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
		Assurance: resource.AssuranceDevelopment,
	}, resource.Dependencies{
		AccessTokens:    jwt,
		Replay:          memstore.NewReplayStore(),
		Revocation:      resource.NoRevocation{},
		Clock:           fixedClock{now: h.now},
		SubjectResolver: resolver,
	})
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	return verifier
}

// TestReversiblePairwiseRefusesALongInternalSubject: an internal subject
// NewSubjectID accepts but NewReversible can't hold fails the completion
// closed, with no code, and the error names the limit rather than
// reporting an opaque derivation failure.
func TestReversiblePairwiseRefusesALongInternalSubject(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.Reversible, reversiblePairwise(t))
	long := strings.Repeat("u", pairwise.MaxReversibleSubjectLength+1)
	required := interactionFor(t, h, nil)
	completed, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: required.Handle, Result: authorizedAs(t, h, long)})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	local, ok := completed.(server.AuthorizationLocalError)
	if !ok || local.Error.Code() != server.ErrorServerError {
		t.Fatalf("result = %#v, want a server_error local error", completed)
	}
	if desc := local.Error.PublicDescription(); !strings.Contains(desc, "151-byte limit") {
		t.Errorf("description = %q, want it to name the 151-byte limit", desc)
	}
	if n := len(h.grants.codes); n != 0 {
		t.Errorf("%d authorization codes stored, want none", n)
	}
	if _, err := h.server.ClientSubject(context.Background(), testClientID, mustAuthenticated(t, strings.Repeat("u", pairwise.MaxReversibleSubjectLength))); err != nil {
		t.Errorf("ClientSubject(151-byte subject) = %v, want it derived", err)
	}
}
