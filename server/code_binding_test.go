package server_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// These tests cover what an authorization code is bound to besides its
// value: the code_verifier of its PKCE challenge, its redirect_uri, and
// the DPoP key its dpop_jkt names. A token request presenting the code
// without one of them finds no code, so it neither spends the code nor,
// once it's redeemed, revokes what it issued (RFC 6749 §4.1.2), even
// from the code's own client: a web client that an attacker delivers a
// leaked code to, in a sign-in of their own, presents it that way.

// unregisteredRedirectURI is a redirect URI no test client registers.
const unregisteredRedirectURI = "https://attacker.example/callback"

// codePresentation is what a token request presents with a code.
type codePresentation struct {
	verifier, redirectURI string
	dpopKey               *ecdsa.PrivateKey
}

// presentCode exchanges code as p describes, authenticated as
// testClientID.
func presentCode(t *testing.T, h harness, code string, p codePresentation) (server.TokenResult, error) {
	t.Helper()
	return h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, p.redirectURI, p.verifier)},
		DPoPProofs: []string{createDPoPProof(t, p.dpopKey, h.now)},
	})
}

// missingBinding says which of what a code is bound to a presentation
// gets wrong.
type missingBinding struct{ verifier, redirectURI, dpopKey bool }

// missingBindings are the presentations of a code missing one thing it
// is bound to, and missing all three, as an attacker's sign-in at the
// code's own client presents it.
var missingBindings = map[string]missingBinding{
	"another code_verifier":        {verifier: true},
	"an unregistered redirect_uri": {redirectURI: true},
	"another DPoP key":             {dpopKey: true},
	"none of them":                 {verifier: true, redirectURI: true, dpopKey: true},
}

// of is own, the code's own presentation, with what m names changed.
func (m missingBinding) of(t *testing.T, own codePresentation) codePresentation {
	t.Helper()
	if m.verifier {
		own.verifier = wrongCodeVerifier
	}
	if m.redirectURI {
		own.redirectURI = unregisteredRedirectURI
	}
	if m.dpopKey {
		own.dpopKey = generateKey(t)
	}
	return own
}

// dpopBoundCode pushes an authorization request with a DPoP proof made
// with dpopKey, so its code is bound to that key (RFC 9449 §10), and
// returns the code its authorization, granting offline_access, issues.
func dpopBoundCode(t *testing.T, h harness, dpopKey *ecdsa.PrivateKey) string {
	t.Helper()
	ctx := context.Background()
	push, err := h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", testCodeChallenge),
			formParam("code_challenge_method", "S256"),
		}},
		DPoPProofs: []string{createDPoPProofForPAR(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("BeginAuthorization = %T, want InteractionRequired", action)
	}
	completed, err := h.server.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: authorizeWithGrantID(t, h.now, "", "openid", "accounts", "offline_access"),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := completed.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T, want AuthorizationRedirect", completed)
	}
	dest := redirect.Destination().URL()
	return dest.Query().Get("code")
}

// harnessOnStepClock is newHarness's server reading a clock the test
// moves on with movedOn.
func harnessOnStepClock(t *testing.T) (harness, *stepClock) {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	clock := &stepClock{now: h.now}
	return withDependencies(t, h, func(d *server.Dependencies) { d.Clock = clock }), clock
}

// movedOn is h with its server's clock, and its own time, moved on by d.
func movedOn(h harness, clock *stepClock, d time.Duration) harness {
	clock.advance(d)
	h.now = h.now.Add(d)
	return h
}

// TestCodeReuseWithoutItsBindingRevokesNothing covers a redeemed code
// presented again by its own client, within the code's lifetime and
// after it, without its code_verifier, its redirect_uri or its DPoP key:
// refused, revoking nothing, so the user's tokens keep working. The
// client presenting all three again is a reuse, which still revokes
// them.
func TestCodeReuseWithoutItsBindingRevokesNothing(t *testing.T) {
	for name, missing := range missingBindings {
		for _, later := range []time.Duration{0, 2 * time.Minute} {
			t.Run(fmt.Sprintf("%s, %v after the exchange", name, later), func(t *testing.T) {
				requireReuseWithoutBindingRevokesNothing(t, missing, later)
			})
		}
	}
}

// requireReuseWithoutBindingRevokesNothing redeems a code bound to a
// DPoP key, presents it again later as missing describes, and requires
// that presentation refused without revoking or auditing a revocation,
// the code's refresh token still working, and the code's own
// presentation after it still revoking the token.
func requireReuseWithoutBindingRevokesNothing(t *testing.T, missing missingBinding, later time.Duration) {
	t.Helper()
	h, clock := harnessOnStepClock(t)
	own := codePresentation{verifier: testCodeVerifier, redirectURI: testRedirectURI, dpopKey: generateKey(t)}
	code := dpopBoundCode(t, h, own.dpopKey)
	first, err := presentCode(t, h, code, own)
	if err != nil || !first.HasRefreshToken {
		t.Fatalf("ExchangeAuthorizationCode = %v (refresh token %v)", err, first.HasRefreshToken)
	}
	h = movedOn(h, clock, later)
	revoked, audited := len(h.revocation.all()), len(h.audit.all())

	_, err = presentCode(t, h, code, missing.of(t, own))
	requireInvalidGrant(t, err)
	if added := h.revocation.all()[revoked:]; len(added) != 0 {
		t.Fatalf("the presentation revoked %v", added)
	}
	requireNoRevokingReuseAudited(t, h.audit.all()[audited:])
	if _, err := refreshWith(t, h, first.RefreshToken.Reveal(), ""); err != nil {
		t.Fatalf("refresh after the presentation: %v", err)
	}

	_, err = presentCode(t, h, code, own)
	requireInvalidGrant(t, err)
	if _, err := refreshWith(t, h, first.RefreshToken.Reveal(), ""); err == nil {
		t.Fatal("refresh succeeded after the code's own client presented it again")
	}
}

// TestCodeIsNotSpentWithoutItsBinding covers a code not yet redeemed,
// presented by its own client without its code_verifier, its
// redirect_uri or its DPoP key: refused without spending it, so the
// user's own exchange still succeeds.
func TestCodeIsNotSpentWithoutItsBinding(t *testing.T) {
	for name, missing := range missingBindings {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			own := codePresentation{verifier: testCodeVerifier, redirectURI: testRedirectURI, dpopKey: generateKey(t)}
			code := dpopBoundCode(t, h, own.dpopKey)
			_, err := presentCode(t, h, code, missing.of(t, own))
			requireInvalidGrant(t, err)
			if _, err := presentCode(t, h, code, own); err != nil {
				t.Fatalf("the code's own exchange after the presentation: %v", err)
			}
		})
	}
}

// countingGrants is a GrantStore counting its RedeemAuthorizationCode
// calls, which fail with fail when it's set.
type countingGrants struct {
	storage.GrantStore

	mu      sync.Mutex
	redeems int
	fail    error
}

func (g *countingGrants) RedeemAuthorizationCode(ctx context.Context, redemption storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	g.mu.Lock()
	g.redeems++
	fail := g.fail
	g.mu.Unlock()
	if fail != nil {
		return storage.RedeemedAuthorizationCode{}, fail
	}
	return g.GrantStore.RedeemAuthorizationCode(ctx, redemption)
}

func (g *countingGrants) redeemCalls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.redeems
}

// harnessCountingRedemptions is newHarness's server over a
// countingGrants of its own GrantStore.
func harnessCountingRedemptions(t *testing.T) (harness, *countingGrants) {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	grants := &countingGrants{GrantStore: h.grants}
	return withDependencies(t, h, func(d *server.Dependencies) { d.Grants = grants }), grants
}

// TestMalformedCodeVerifierIsRefusedBeforeTheStore covers a
// code_verifier RFC 7636 §4.1 doesn't allow: it has no challenge, so it
// can't match the code's. It's refused as one that doesn't, without
// asking the store for the code, which stays unspent.
func TestMalformedCodeVerifierIsRefusedBeforeTheStore(t *testing.T) {
	h, grants := harnessCountingRedemptions(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	dpopKey := generateKey(t)
	for name, verifier := range map[string]string{
		"too short":              testCodeVerifier[:42],
		"too long":               strings.Repeat("a", 129),
		"a disallowed character": testCodeVerifier[:42] + "+",
	} {
		_, err := presentCode(t, h, code, codePresentation{verifier: verifier, redirectURI: testRedirectURI, dpopKey: dpopKey})
		if serverErrorCode(t, err) != server.ErrorInvalidGrant || serverErrorDescription(t, err) != "code_verifier does not match code_challenge" {
			t.Errorf("a code_verifier %s: %v, want invalid_grant: code_verifier does not match code_challenge", name, err)
		}
	}
	if calls := grants.redeemCalls(); calls != 0 {
		t.Fatalf("RedeemAuthorizationCode calls = %d, want none", calls)
	}
	if _, err := presentCode(t, h, code, codePresentation{verifier: testCodeVerifier, redirectURI: testRedirectURI, dpopKey: dpopKey}); err != nil {
		t.Fatalf("the code's own exchange after them: %v", err)
	}
}

// TestCodeLookupsFollowTheDPoPBinding covers where an exchange looks for
// a DPoP-bound client's code: under the presented proof's key first, so
// a code bound to that key is found at once, then under none, where a
// code bound to no key is.
func TestCodeLookupsFollowTheDPoPBinding(t *testing.T) {
	h, grants := harnessCountingRedemptions(t)
	dpopKey := generateKey(t)
	for name, tc := range map[string]struct {
		code    string
		lookups int
	}{
		"a code bound to the presented key": {dpopBoundCode(t, h, dpopKey), 1},
		"a code bound to no key":            {completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"}), 2},
	} {
		before := grants.redeemCalls()
		if _, err := presentCode(t, h, tc.code, codePresentation{verifier: testCodeVerifier, redirectURI: testRedirectURI, dpopKey: dpopKey}); err != nil {
			t.Fatalf("%s: ExchangeAuthorizationCode: %v", name, err)
		}
		if lookups := grants.redeemCalls() - before; lookups != tc.lookups {
			t.Errorf("%s: RedeemAuthorizationCode calls = %d, want %d", name, lookups, tc.lookups)
		}
	}
}

// TestCodeLookupOutageIsNotRetriedWithoutTheDPoPKey covers a store that
// couldn't answer the lookup of a code under the presented DPoP key:
// 500 server_error, without looking again under no key, where a store
// that had recovered would miss a code bound to the presented one.
func TestCodeLookupOutageIsNotRetriedWithoutTheDPoPKey(t *testing.T) {
	h, grants := harnessCountingRedemptions(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	grants.fail = errStoreDown
	_, err := presentCode(t, h, code, codePresentation{verifier: testCodeVerifier, redirectURI: testRedirectURI, dpopKey: generateKey(t)})
	checkServerError(t, err, server.ErrorServerError, 500)
	if calls := grants.redeemCalls(); calls != 1 {
		t.Fatalf("RedeemAuthorizationCode calls = %d, want 1", calls)
	}
}

// TestCodeExchangeRequiresWhatTheCodeIsLookedUpWith covers a token
// request leaving out the code, the redirect_uri or the code_verifier
// it's looked up with: refused before the store is asked for anything.
func TestCodeExchangeRequiresWhatTheCodeIsLookedUpWith(t *testing.T) {
	h, grants := harnessCountingRedemptions(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	for name, tc := range map[string]struct {
		code string
		p    codePresentation
		want server.ErrorCode
	}{
		"no code":          {"", codePresentation{verifier: testCodeVerifier, redirectURI: testRedirectURI}, server.ErrorInvalidRequest},
		"no redirect_uri":  {code, codePresentation{verifier: testCodeVerifier}, server.ErrorInvalidRequest},
		"no code_verifier": {code, codePresentation{redirectURI: testRedirectURI}, server.ErrorInvalidGrant},
	} {
		tc.p.dpopKey = generateKey(t)
		if _, err := presentCode(t, h, tc.code, tc.p); serverErrorCode(t, err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
	if calls := grants.redeemCalls(); calls != 0 {
		t.Fatalf("RedeemAuthorizationCode calls = %d, want none", calls)
	}
}

// digestBlindGrants is a GrantStore that answers every redemption with
// the last code it stored, whatever digest it's asked for, as a store
// that doesn't key codes by their digest would.
type digestBlindGrants struct {
	storage.GrantStore

	mu   sync.Mutex
	last [32]byte
}

func (g *digestBlindGrants) CreateAuthorizationCode(ctx context.Context, code storage.NewAuthorizationCode) error {
	g.mu.Lock()
	g.last = code.CodeHash
	g.mu.Unlock()
	return g.GrantStore.CreateAuthorizationCode(ctx, code)
}

func (g *digestBlindGrants) RedeemAuthorizationCode(ctx context.Context, redemption storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	g.mu.Lock()
	redemption.CodeHash = g.last
	g.mu.Unlock()
	return g.GrantStore.RedeemAuthorizationCode(ctx, redemption)
}

// TestRedeemedCodeIsCheckedAgainstItsBinding covers a store that returns
// a code for a digest it wasn't stored under: the redeemed record's own
// PKCE challenge, redirect URI and dpop_jkt still refuse a presentation
// without them, as its client instance does (checkCodeInstance). The
// other redirect URI is registered too, so the exchange reaches the
// record (checkCodeExchangeRequest refuses an unregistered one first).
func TestRedeemedCodeIsCheckedAgainstItsBinding(t *testing.T) {
	for name, tc := range map[string]struct {
		missing missingBinding
		want    string
	}{
		"another code_verifier":           {missingBinding{verifier: true}, "code_verifier does not match code_challenge"},
		"another registered redirect_uri": {missingBinding{redirectURI: true}, "redirect_uri does not match the authorization request"},
		"another DPoP key":                {missingBinding{dpopKey: true}, "DPoP proof key does not match the dpop_jkt bound to this authorization code"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			h = withDependencies(t, h, func(d *server.Dependencies) { d.Grants = &digestBlindGrants{GrantStore: h.grants} })
			own := codePresentation{verifier: testCodeVerifier, redirectURI: testRedirectURI, dpopKey: generateKey(t)}
			code := dpopBoundCode(t, h, own.dpopKey)
			reregisterRedirectURIs(t, h, testRedirectURI, unregisteredRedirectURI)
			_, err := presentCode(t, h, code, tc.missing.of(t, own))
			if serverErrorCode(t, err) != server.ErrorInvalidGrant || serverErrorDescription(t, err) != tc.want {
				t.Fatalf("%v, want invalid_grant: %s", err, tc.want)
			}
		})
	}
}
