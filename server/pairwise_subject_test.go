package server_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// testPairwisePrefix is the Prefix every pairwise test server puts in
// front of its pairwise subs.
const testPairwisePrefix = "pw:"

// hmacDeriver is NewHMAC under a fixed test key.
func hmacDeriver(t *testing.T) pairwise.Deriver {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	d, err := pairwise.NewHMAC(key)
	if err != nil {
		t.Fatalf("NewHMAC: %v", err)
	}
	return d
}

// mappingDeriver is a Deriver that can look its bodies up again, as a
// Reversible deployment's must: the body is an HMAC of its input, and a
// table maps it back.
type mappingDeriver struct {
	mu       sync.Mutex
	subjects map[string]string // issuer, sector, body → internal subject
}

func newMappingDeriver() *mappingDeriver {
	return &mappingDeriver{subjects: map[string]string{}}
}

func (m *mappingDeriver) DerivePairwiseSubject(_ context.Context, in pairwise.Input) (string, error) {
	if in.IsZero() {
		return "", errors.New("mapping: zero input")
	}
	mac := hmac.New(sha256.New, []byte("mapping-deriver-test-key"))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(in.Issuer()), in.Issuer(), len(in.Sector()), in.Sector(), len(in.Subject()), in.Subject())
	body := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subjects[in.Issuer()+"\x00"+in.Sector()+"\x00"+body] = in.Subject()
	return body, nil
}

func (m *mappingDeriver) LookupInternalSubject(_ context.Context, issuer, sector, body string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	subject, ok := m.subjects[issuer+"\x00"+sector+"\x00"+body]
	if !ok {
		return "", fmt.Errorf("mapping: %w", pairwise.ErrSubjectNotFound)
	}
	return subject, nil
}

// TestMappingDeriverContract keeps the test deriver honest.
func TestMappingDeriverContract(t *testing.T) {
	shared := newMappingDeriver()
	pairwise.TestDeriverContract(t, func(*testing.T) pairwise.Deriver { return shared })
}

// mustPrefix builds a pairwise.Prefix.
func mustPrefix(t *testing.T, value string) pairwise.Prefix {
	t.Helper()
	p, err := pairwise.NewPrefix(value)
	if err != nil {
		t.Fatalf("NewPrefix: %v", err)
	}
	return p
}

// pairwiseClient is a client config like the harnesses' testClientID,
// registered for pairwise subjects; ciba builds the CIBA harness's.
func pairwiseClient(ciba bool) storage.RegisteredClientConfig {
	cfg := storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
		SubjectType:              fapi.SubjectTypePairwise,
	}
	if ciba {
		cfg.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
		// A client permitted CIBA derives no sector from its redirect
		// URIs, so it names the one they're on.
		cfg.Sector = "rp.example"
	} else {
		cfg.RequestObjectAlgorithm = fapi.ES256
	}
	return cfg
}

// register replaces (or adds) a client in h's repository.
func register(t *testing.T, h harness, cfg storage.RegisteredClientConfig) {
	t.Helper()
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[cfg.ID] = client
}

// withPairwise rebuilds h's server, over the same stores, with
// testClientID registered as client and pairwise subjects derived by
// deriver.
func withPairwise(t *testing.T, h harness, client storage.RegisteredClientConfig, deriver pairwise.Deriver) harness {
	t.Helper()
	register(t, h, client)
	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePublic, Enforcement: server.SubjectTypesPerClient,
		Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = deriver
	if _, reversible := deriver.(pairwise.Lookup); !reversible {
		// A one-way pairwise sub can't be mapped back, so the internal
		// subject stays in a server-side token record.
		h.deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
	}
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	return h
}

// clientSubjectOf is h's server's sub for user at testClientID.
func clientSubjectOf(t *testing.T, h harness, user string) string {
	t.Helper()
	sub, err := h.server.ClientSubject(context.Background(), testClientID, mustAuthenticated(t, user))
	if err != nil {
		t.Fatalf("ClientSubject: %v", err)
	}
	return sub
}

func mustAuthenticated(t *testing.T, user string) server.AuthenticatedSubject {
	t.Helper()
	subject, err := server.NewAuthenticatedSubject(mustSubjectID(t, user))
	if err != nil {
		t.Fatal(err)
	}
	return subject
}

// TestPairwiseSubjectInIDTokens covers OpenID Connect Core §8 and §12.2:
// a pairwise client's ID tokens carry its pairwise sub for the user (the
// configured prefix and a derived body, never the internal subject), the
// same one at every authorization, and the same one again on refresh.
func TestPairwiseSubjectInIDTokens(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), hmacDeriver(t))
	want := clientSubjectOf(t, h, "user-1")
	if !strings.HasPrefix(want, testPairwisePrefix) || strings.Contains(want, "user-1") {
		t.Fatalf("ClientSubject = %q, want the prefix and a derived body", want)
	}

	first, _ := exchangeForTokensWithOfflineAccess(t, h)
	if got := validateIDToken(t, h, first.IDToken.Reveal(), first.AccessToken.Reveal()).Subject; got != want {
		t.Errorf("ID token sub = %q, want %q", got, want)
	}
	refreshed, err := refreshWith(t, h, first.RefreshToken.Reveal(), "")
	if err != nil || !refreshed.HasIDToken {
		t.Fatalf("refresh = %v (ID token %v), want an ID token", err, refreshed.HasIDToken)
	}
	if got := validateIDToken(t, h, refreshed.IDToken.Reveal(), refreshed.AccessToken.Reveal()).Subject; got != want {
		t.Errorf("refreshed ID token sub = %q, want %q", got, want)
	}
	again, _ := exchangeForTokensWithOfflineAccess(t, h)
	if got := validateIDToken(t, h, again.IDToken.Reveal(), again.AccessToken.Reveal()).Subject; got != want {
		t.Errorf("second authorization's ID token sub = %q, want %q", got, want)
	}
}

// TestPublicClientKeepsItsSubject: next to a pairwise client, a public
// one's ID tokens still carry the user's own subject.
func TestPublicClientKeepsItsSubject(t *testing.T) {
	public := pairwiseClient(false)
	public.SubjectType = fapi.SubjectTypePublic
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), public, hmacDeriver(t))
	if got := clientSubjectOf(t, h, "user-1"); got != "user-1" {
		t.Errorf("ClientSubject = %q, want user-1", got)
	}
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	if got := exchangeForValidatedIDToken(t, h, code).Subject; got != "user-1" {
		t.Errorf("ID token sub = %q, want user-1", got)
	}
}

// TestPairwiseSubjectBySector: the same user gets different pairwise
// subs at clients of different sectors, the same one at clients of one
// sector, and different users get different ones.
func TestPairwiseSubjectBySector(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), hmacDeriver(t))
	sameSector := pairwiseClient(false)
	sameSector.ID = "same-sector-client"
	sameSector.RedirectURIs = []fapi.RegisteredRedirectURI{"https://rp.example/other-callback"}
	otherSector := pairwiseClient(false)
	otherSector.ID = "other-sector-client"
	otherSector.RedirectURIs = []fapi.RegisteredRedirectURI{"https://other-rp.example/callback"}
	register(t, h, sameSector)
	register(t, h, otherSector)

	subjectAt := func(clientID fapi.ClientID, user string) string {
		sub, err := h.server.ClientSubject(context.Background(), clientID, mustAuthenticated(t, user))
		if err != nil {
			t.Fatalf("ClientSubject(%s): %v", clientID, err)
		}
		return sub
	}
	base := subjectAt(testClientID, "user-1")
	if got := subjectAt(sameSector.ID, "user-1"); got != base {
		t.Errorf("sub at a client of the same sector = %q, want %q", got, base)
	}
	if got := subjectAt(otherSector.ID, "user-1"); got == base {
		t.Errorf("sub at a client of another sector = %q, the same as at the first", got)
	}
	if got := subjectAt(testClientID, "user-2"); got == base {
		t.Errorf("another user's sub = %q, the same as user-1's", got)
	}
}

// TestPairwiseSubjectSurvivesConfigurationChange covers grant continuity:
// a grant keeps the sub it was issued with when the client's sector
// later changes, so its refreshed ID tokens keep it too (OIDC Core
// §12.2); a new authorization gets the new sector's sub.
func TestPairwiseSubjectSurvivesConfigurationChange(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), hmacDeriver(t))
	before := clientSubjectOf(t, h, "user-1")
	first, _ := exchangeForTokensWithOfflineAccess(t, h)

	moved := pairwiseClient(false)
	moved.Sector = "moved.example"
	register(t, h, moved)
	after := clientSubjectOf(t, h, "user-1")
	if after == before {
		t.Fatalf("ClientSubject is %q in both sectors", after)
	}

	refreshed, err := refreshWith(t, h, first.RefreshToken.Reveal(), "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := validateIDToken(t, h, refreshed.IDToken.Reveal(), refreshed.AccessToken.Reveal()).Subject; got != before {
		t.Errorf("refreshed ID token sub = %q, want the grant's own %q", got, before)
	}
	again, _ := exchangeForTokensWithOfflineAccess(t, h)
	if got := validateIDToken(t, h, again.IDToken.Reveal(), again.AccessToken.Reveal()).Subject; got != after {
		t.Errorf("new authorization's ID token sub = %q, want %q", got, after)
	}
}

// TestPairwisePrefixChangeEndsGrants: a resource server strips the
// current prefix to look a pairwise sub up, so a grant whose sub was
// issued under another prefix is refused at its next use, rather than
// issuing tokens no resource server could resolve. New authorizations
// get subs under the new prefix.
func TestPairwisePrefixChangeEndsGrants(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), reversiblePairwise(t))
	first, _ := exchangeForTokensWithOfflineAccess(t, h)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	h.cfg.Subjects.Prefix = mustPrefix(t, "changed:")
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv

	if _, err := refreshWith(t, h, first.RefreshToken.Reveal(), ""); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Errorf("refresh of a grant issued under the old prefix = %v, want invalid_grant", err)
	}
	_, err = h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Errorf("exchange of a code issued under the old prefix = %v, want invalid_grant", err)
	}
	again, _ := exchangeForTokensWithOfflineAccess(t, h)
	if got := validateIDToken(t, h, again.IDToken.Reveal(), again.AccessToken.Reveal()).Subject; !strings.HasPrefix(got, "changed:") {
		t.Errorf("new authorization's ID token sub = %q, want the new prefix", got)
	}
}

// TestLegacyGrantKeepsItsSubject: a grant record written before
// client_sub existed issues the internal subject, as it always did.
func TestLegacyGrantKeepsItsSubject(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), hmacDeriver(t))
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	forgetClientSubject(t, h)
	if got := exchangeForValidatedIDToken(t, h, code).Subject; got != "user-1" {
		t.Errorf("ID token sub from a record without client_sub = %q, want user-1", got)
	}
}

// forgetClientSubject rewrites every stored authorization code's grant
// without client_sub, as a record written before it existed is.
func forgetClientSubject(t *testing.T, h harness) {
	t.Helper()
	h.grants.mu.Lock()
	defer h.grants.mu.Unlock()
	for hash, code := range h.grants.byHash {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(code.Grant, &record); err != nil {
			t.Fatal(err)
		}
		if _, ok := record["client_sub"]; !ok {
			t.Fatal("the stored grant has no client_sub to forget")
		}
		delete(record, "client_sub")
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		code.Grant = raw
		h.grants.byHash[hash] = code
	}
}

// TestPairwiseRequiredSubject covers OIDC Core §5.5.1 for a pairwise
// client: its id_token_hint or "sub" value names the user by the
// pairwise sub it was given, and only that user may complete. Under
// a one-way deriver the interaction shows that sub (compare it with
// ClientSubject); with a lookup, the user's own subject.
func TestPairwiseRequiredSubject(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reversible bool
		deriver    func(t *testing.T) pairwise.Deriver
		hint       bool
		user       string
		wantError  string
	}{
		{name: "one-way, hint, same user", deriver: hmacDeriver, hint: true, user: "user-1"},
		{name: "one-way, hint, different user", deriver: hmacDeriver, hint: true, user: "user-2", wantError: "login_required"},
		{name: "one-way, sub value, different user", deriver: hmacDeriver, user: "user-2", wantError: "login_required"},
		{name: "reversible, hint, same user", reversible: true, deriver: func(*testing.T) pairwise.Deriver { return newMappingDeriver() }, hint: true, user: "user-1"},
		{name: "reversible, sub value, different user", reversible: true, deriver: func(*testing.T) pairwise.Deriver { return newMappingDeriver() }, user: "user-2", wantError: "login_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), tc.deriver(t))
			sub := clientSubjectOf(t, h, "user-1")
			extra := map[string]string{"claims": subClaims("id_token", sub)}
			if tc.hint {
				extra = map[string]string{"id_token_hint": serverHint(t, h, func(c map[string]any) { c["sub"] = sub })}
			}
			required := interactionFor(t, h, extra)
			wantShown := sub
			if tc.reversible {
				wantShown = "user-1"
			}
			if got := required.Interaction.RequiredSubject; got != wantShown {
				t.Errorf("RequiredSubject = %q, want %q", got, wantShown)
			}
			assertCompletionOutcome(t, h, completeAs(t, h, required, tc.user), tc.wantError)
		})
	}
}

// TestPairwiseRequiredSubjectUnknownToLookup: with a lookup, a pairwise
// sub this server never issued to the client (another client's, the
// internal subject, or a made-up one) names no one, and the request is
// invalid_request.
func TestPairwiseRequiredSubjectUnknownToLookup(t *testing.T) {
	for name, sub := range map[string]string{
		"internal subject": "user-1",
		"made up":          testPairwisePrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		t.Run(name, func(t *testing.T) {
			h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), newMappingDeriver())
			err := pushPAR(t, h, map[string]string{"claims": subClaims("id_token", sub)})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("PushAuthorizationRequest error code = %q, want invalid_request", code)
			}
		})
	}
}

// pushPAR pushes a plain-form request with extra parameters and returns
// the error.
func pushPAR(t *testing.T, h harness, extra map[string]string) error {
	t.Helper()
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), extra)},
	})
	return err
}

// TestPairwiseCIBA covers the CIBA flow for a pairwise client: the ID
// token carries the pairwise sub; an id_token_hint can identify the user
// only when the server can map pairwise subs back, and is invalid_request
// with a one-way deriver; a "claims" sub value is enforced either way.
func TestPairwiseCIBA(t *testing.T) {
	t.Run("ID token sub", func(t *testing.T) {
		h := cibaWithPairwise(t, hmacDeriver(t))
		required := beginBackchannel(t, h, standardBackchannelParams(t))
		approveBackchannelAs(t, h, required, "user-1")
		result, err := exchangeCIBA(t, h, required.AuthReqID.String())
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		want := clientSubjectOf(t, h, "user-1")
		if got := validateIDToken(t, h, result.IDToken.Reveal(), result.AccessToken.Reveal()).Subject; got != want {
			t.Errorf("ID token sub = %q, want %q", got, want)
		}
		// The access token's server-side record keeps the internal
		// subject, and the client's sub beside it.
		store := h.deps.AccessTokens.(server.OpaqueAccessTokens).Store.(*memstore.AccessTokenStore)
		assertOpaqueRecordSubjects(t, store, result.AccessToken.Reveal(), "user-1", want, "rp.example")
	})
	t.Run("one-way refuses id_token_hint", func(t *testing.T) {
		h := cibaWithPairwise(t, hmacDeriver(t))
		params := standardBackchannelParams(t)
		delete(params, "login_hint")
		params["id_token_hint"] = jsonRaw(t, serverHint(t, h, func(c map[string]any) { c["sub"] = clientSubjectOf(t, h, "user-1") }))
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
		})
		if err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		if local, ok := action.(server.BackchannelAuthenticationLocalError); !ok || local.Error.Code() != server.ErrorInvalidRequest {
			t.Fatalf("action = %#v, want an invalid_request local error", action)
		}
	})
	t.Run("one-way enforces a sub value", func(t *testing.T) {
		h := cibaWithPairwise(t, hmacDeriver(t))
		params := standardBackchannelParams(t)
		sub := clientSubjectOf(t, h, "user-1")
		params["claims"] = json.RawMessage(subClaims("id_token", sub))
		required := beginBackchannel(t, h, params)
		assertBackchannelRequiredSubject(t, h, required, sub)
		approveBackchannelAs(t, h, required, "user-2")
		result, err := exchangeCIBA(t, h, required.AuthReqID.String())
		assertTokensOrAccessDenied(t, result, err, true)
	})
	for _, user := range []string{"user-1", "user-2"} {
		t.Run("reversible resolves id_token_hint, "+user, func(t *testing.T) {
			h := cibaWithPairwise(t, newMappingDeriver())
			params := standardBackchannelParams(t)
			delete(params, "login_hint")
			params["id_token_hint"] = jsonRaw(t, serverHint(t, h, func(c map[string]any) { c["sub"] = clientSubjectOf(t, h, "user-1") }))
			required := beginBackchannel(t, h, params)
			assertBackchannelRequiredSubject(t, h, required, "user-1")
			approveBackchannelAs(t, h, required, user)
			result, err := exchangeCIBA(t, h, required.AuthReqID.String())
			assertTokensOrAccessDenied(t, result, err, user != "user-1")
		})
	}
}

// cibaWithPairwise is a CIBA harness whose client is pairwise.
func cibaWithPairwise(t *testing.T, deriver pairwise.Deriver) harness {
	t.Helper()
	h, _ := newHarnessWithBackchannel(t)
	return withPairwise(t, h, pairwiseClient(true), deriver)
}

// approveBackchannelAs completes required as user.
func approveBackchannelAs(t *testing.T, h harness, required server.BackchannelInteractionRequired, user string) {
	t.Helper()
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizedAs(t, h, user),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
}

// TestPairwiseSubjectFailsClosed: a pairwise client whose sub can't be
// derived gets no code, never one for the internal subject. A
// pairwise-only server with a client registered public, and a pairwise
// client of a server without a deriver, are refused at PAR, before the
// user logs in; a deriver failing, or a client changed after its
// request was pushed, fails at completion.
func TestPairwiseSubjectFailsClosed(t *testing.T) {
	t.Run("deriver fails", func(t *testing.T) {
		h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), failingDeriver{hmacDeriver(t)})
		assertCompletionServerError(t, h)
	})
	t.Run("public client under pairwise only", func(t *testing.T) {
		h := pairwiseOnlyHarness(t)
		public := pairwiseClient(false)
		public.SubjectType = fapi.SubjectTypePublic
		register(t, h, public)
		assertPARServerError(t, h)
	})
	t.Run("client turned public after its request", func(t *testing.T) {
		h := pairwiseOnlyHarness(t)
		required := interactionFor(t, h, nil)
		public := pairwiseClient(false)
		public.SubjectType = fapi.SubjectTypePublic
		register(t, h, public)
		completed, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: required.Handle, Result: authorizedAs(t, h, "user-1")})
		if err != nil {
			t.Fatalf("CompleteAuthorization: %v", err)
		}
		if local, ok := completed.(server.AuthorizationLocalError); !ok || local.Error.Code() != server.ErrorServerError {
			t.Fatalf("result = %#v, want a server_error local error", completed)
		}
	})
	t.Run("no deriver", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		register(t, h, pairwiseClient(false))
		srv, err := server.New(h.cfg, h.deps)
		if err != nil {
			t.Fatalf("server.New: %v", err)
		}
		h.server = srv
		assertPARServerError(t, h)
	})
}

// pairwiseOnlyHarness is a harness whose server issues only pairwise
// subs, with testClientID registered pairwise.
func pairwiseOnlyHarness(t *testing.T) harness {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	register(t, h, pairwiseClient(false))
	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPairwiseOnly,
		Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = hmacDeriver(t)
	h.deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	return h
}

// assertPARServerError pushes an authorization request for testClientID
// and checks it's refused with server_error, before any interaction.
func assertPARServerError(t *testing.T, h harness) {
	t.Helper()
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("PushAuthorizationRequest = %v, want server_error", err)
	}
}

// failingDeriver derives the fixed input New probes with, and fails for
// every other.
type failingDeriver struct{ pairwise.Deriver }

func (f failingDeriver) DerivePairwiseSubject(ctx context.Context, in pairwise.Input) (string, error) {
	if strings.HasPrefix(in.Subject(), "fapigo-pairwise-probe") { // New's startup probe
		return f.Deriver.DerivePairwiseSubject(ctx, in)
	}
	return "", errors.New("deriver unavailable")
}

// assertCompletionServerError completes an authorization as user-1 and
// checks it fails locally with server_error, with no code stored.
func assertCompletionServerError(t *testing.T, h harness) {
	t.Helper()
	required := interactionFor(t, h, nil)
	completed, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: required.Handle, Result: authorizedAs(t, h, "user-1")})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	local, ok := completed.(server.AuthorizationLocalError)
	if !ok || local.Error.Code() != server.ErrorServerError {
		t.Fatalf("result = %#v, want a server_error local error", completed)
	}
	if n := len(h.grants.codes); n != 0 {
		t.Errorf("%d authorization codes stored, want none", n)
	}
}

// TestClientSubjectRefusals: ClientSubject needs a registered client and
// an authenticated subject.
func TestClientSubjectRefusals(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), hmacDeriver(t))
	if _, err := h.server.ClientSubject(context.Background(), "unknown-client", mustAuthenticated(t, "user-1")); serverErrorCode(t, err) != server.ErrorInvalidClient {
		t.Errorf("ClientSubject(unknown client) = %v, want invalid_client", err)
	}
	public := pairwiseClient(false)
	public.ID = "public-client"
	public.SubjectType = fapi.SubjectTypePublic
	register(t, h, public)
	for _, clientID := range []fapi.ClientID{testClientID, public.ID} {
		if _, err := h.server.ClientSubject(context.Background(), clientID, server.AuthenticatedSubject{}); serverErrorCode(t, err) != server.ErrorServerError {
			t.Errorf("ClientSubject(%s, zero subject) = %v, want server_error", clientID, err)
		}
	}
}

// TestEmbedderGrantStoresPairwiseSubject: a grant the embedder served
// (IssueRefreshToken) gets the client's sub through the same central
// resolution as the server's own grants, and a pairwise client of a
// server without a deriver gets nothing.
func TestEmbedderGrantStoresPairwiseSubject(t *testing.T) {
	attesterKey := generateKey(t)
	h := newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
		c.AllowedScopes = []string{"accounts"}
		c.SubjectType = fapi.SubjectTypePairwise
		c.Sector = "wallet.example"
	})
	issue := func(h harness) (fapi.Secret, error) {
		instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
		attested, binding := embedderTokenRequest(t, instance)
		return h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
			GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
			Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
		})
	}
	if _, err := issue(h); serverErrorCode(t, err) != server.ErrorServerError {
		t.Fatalf("IssueRefreshToken without a deriver = %v, want server_error", err)
	}

	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePublic, Enforcement: server.SubjectTypesPerClient,
		Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = hmacDeriver(t)
	accessTokens := memstore.NewAccessTokenStore()
	h.deps.AccessTokens = server.OpaqueAccessTokens{Store: accessTokens}
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	if _, err := issue(h); err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, instance)
	issued, err := h.server.IssueAccessToken(context.Background(), server.IssueAccessTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	var stored struct {
		Subject       string `json:"sub"`
		ClientSubject string `json:"client_sub"`
	}
	refreshTokens := h.grants.refreshTokens
	if len(refreshTokens) != 1 {
		t.Fatalf("%d refresh tokens stored, want 1", len(refreshTokens))
	}
	if err := json.Unmarshal(refreshTokens[0].Grant, &stored); err != nil {
		t.Fatal(err)
	}
	want, err := h.server.ClientSubject(context.Background(), refreshTokens[0].ClientID, mustAuthenticated(t, "holder-1"))
	if err != nil {
		t.Fatalf("ClientSubject: %v", err)
	}
	if stored.Subject != "holder-1" || stored.ClientSubject != want {
		t.Errorf("stored sub, client_sub = %q, %q; want holder-1, %q", stored.Subject, stored.ClientSubject, want)
	}
	// The embedder's first access token carries the same client subject
	// as the refresh grant, the internal one staying in the record.
	assertOpaqueRecordSubjects(t, accessTokens, issued.AccessToken.Reveal(), "holder-1", want, "wallet.example")
}

// TestPairwiseOnlyRefusesGrantsIssuedPublic: a server that switches to
// SubjectTypesPairwiseOnly, which promises every client pairwise subs,
// doesn't keep issuing the user's internal subject from grants made
// while the client was public: their refresh tokens fail with
// invalid_grant, and the client authorizes again. Under
// SubjectTypesPerClient the grant keeps its public sub.
func TestPairwiseOnlyRefusesGrantsIssuedPublic(t *testing.T) {
	for name, tc := range map[string]struct {
		enforcement server.SubjectTypeEnforcement
		wantRefused bool
	}{
		"pairwise only": {server.SubjectTypesPairwiseOnly, true},
		"per client":    {server.SubjectTypesPerClient, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			client := pairwiseClient(false)
			client.SubjectType = 0 // the server's default
			register(t, h, client)
			first, _ := exchangeForTokensWithOfflineAccess(t, h)
			h = switchToPairwise(t, h, tc.enforcement)

			refreshed, err := refreshWith(t, h, first.RefreshToken.Reveal(), "")
			if tc.wantRefused {
				if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
					t.Fatalf("refresh error code = %q, want invalid_grant", code)
				}
				return
			}
			if err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if got := validateIDToken(t, h, refreshed.IDToken.Reveal(), refreshed.AccessToken.Reveal()).Subject; got != "user-1" {
				t.Errorf("refreshed sub = %q, want the grant's public sub kept", got)
			}
		})
	}
}

// switchToPairwise rebuilds h's server, over the same stores, with a
// pairwise default under enforcement.
func switchToPairwise(t *testing.T, h harness, enforcement server.SubjectTypeEnforcement) harness {
	t.Helper()
	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePairwise, Enforcement: enforcement,
		Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = newMappingDeriver()
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	return h
}

// TestSignUserInfoResponseRefusesInternalSubForPairwiseClient: a signed
// UserInfo response for a pairwise client must carry the sub the client
// was given, not the user's internal subject, which an embedder still
// copying AuthorizationContext.InternalSubject would otherwise hand over. A
// public client's sub isn't checked.
func TestSignUserInfoResponseRefusesInternalSubForPairwiseClient(t *testing.T) {
	for name, tc := range map[string]struct {
		deriver pairwise.Deriver
	}{
		"one-way":    {hmacDeriver(t)},
		"reversible": {newMappingDeriver()},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			h.cfg.Algorithms.UserInfo = fapi.ES256
			h = withPairwise(t, h, pairwiseClient(false), tc.deriver)
			client, err := h.clients.ResolveClient(context.Background(), testClientID)
			if err != nil {
				t.Fatal(err)
			}
			clientSub := clientSubjectOf(t, h, "user-1")
			for sub, wantRefused := range map[string]bool{
				clientSub: false,
				"user-1":  true, // the internal subject
				// Well-formed and prefixed, never issued: the prefix already
				// shows it isn't an internal subject, which is all this
				// backstop guards; it may be from the client's earlier sector.
				testPairwisePrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": false,
				"": true,
			} {
				raw, _ := json.Marshal(sub)
				_, serr := h.server.SignUserInfoResponse(context.Background(), client, map[string]json.RawMessage{"sub": raw})
				if refused := serr != nil; refused != wantRefused {
					t.Errorf("sub %q: refused = %v (%v), want %v", sub, refused, serr, wantRefused)
				}
			}
		})
	}
}

// TestPairwiseCIBAOneWayResolverResolvesIDTokenHint: with
// a one-way deriver, an id_token_hint from a pairwise CIBA client is
// refused only when nothing can map its sub back. With a declared
// Dependencies.PairwiseSubjectResolver the hint resolves to its user,
// and a sub the resolver doesn't know is still invalid_request.
func TestPairwiseCIBAOneWayResolverResolvesIDTokenHint(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	resolver := subResolver{subjects: map[[3]string]string{}}
	h.deps.PairwiseSubjectResolver = resolver
	h = withPairwise(t, h, pairwiseClient(true), hmacDeriver(t))
	sub := clientSubjectOf(t, h, "user-1")
	// The embedder records the subs its clients are given.
	resolver.subjects[[3]string{testIssuer, "rp.example", sub}] = "user-1"

	params := standardBackchannelParams(t)
	delete(params, "login_hint")
	params["id_token_hint"] = jsonRaw(t, serverHint(t, h, func(c map[string]any) { c["sub"] = sub }))
	required := beginBackchannel(t, h, params)
	assertBackchannelRequiredSubject(t, h, required, "user-1")

	unknown := standardBackchannelParams(t)
	delete(unknown, "login_hint")
	unknown["id_token_hint"] = jsonRaw(t, serverHint(t, h, func(c map[string]any) { c["sub"] = clientSubjectOf(t, h, "user-2") }))
	assertBackchannelLocalError(t, h, unknown, server.ErrorInvalidRequest)
}

// TestResolveClientSubject: ResolveClientSubject and ResolveIDTokenHint
// map a sub a client was given back to its user wherever the server can
// (a public client, a lookup, a resolver), refuse a sub the client was
// never given, and report ErrNoPairwiseSubjectLookup where nothing can.
func TestResolveClientSubject(t *testing.T) {
	tests := map[string]struct {
		setup    func(t *testing.T) harness
		mappable bool
		pairwise bool
	}{
		"public": {func(t *testing.T) harness { return newHarness(t, server.ProfileFAPISecurity, true) }, true, false},
		"reversible": {func(t *testing.T) harness {
			return withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), newMappingDeriver())
		}, true, true},
		"one-way": {func(t *testing.T) harness {
			return withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), hmacDeriver(t))
		}, false, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := tc.setup(t)
			sub := clientSubjectOf(t, h, "user-1")
			assertResolvesClientSubject(t, h, sub, tc.mappable)
			if tc.mappable && tc.pairwise {
				_, err := h.server.ResolveClientSubject(context.Background(), testClientID, testPairwisePrefix+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
				if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
					t.Errorf("a sub never given: %v, want invalid_request", err)
				}
			}
			if _, err := h.server.ResolveClientSubject(context.Background(), "unknown-client", sub); serverErrorCode(t, err) != server.ErrorInvalidClient {
				t.Errorf("an unknown client: %v, want invalid_client", err)
			}
		})
	}
}

// assertResolvesClientSubject checks that sub, user-1's sub at
// testClientID, resolves to user-1 both directly and through an ID token
// hint carrying it, when mappable, and otherwise reports
// ErrNoPairwiseSubjectLookup.
func assertResolvesClientSubject(t *testing.T, h harness, sub string, mappable bool) {
	t.Helper()
	hint := serverHint(t, h, func(c map[string]any) { c["sub"] = sub })
	for what, resolve := range map[string]func() (string, error){
		"sub":  func() (string, error) { return h.server.ResolveClientSubject(context.Background(), testClientID, sub) },
		"hint": func() (string, error) { return h.server.ResolveIDTokenHint(context.Background(), hint, testClientID) },
	} {
		got, err := resolve()
		switch {
		case !mappable && !errors.Is(err, server.ErrNoPairwiseSubjectLookup):
			t.Errorf("%s: %q, %v; want ErrNoPairwiseSubjectLookup", what, got, err)
		case mappable && (err != nil || got != "user-1"):
			t.Errorf("%s: %q, %v; want user-1", what, got, err)
		}
	}
}

// TestResolveClientSubjectRefusesEmptyAndInvalidInput: an empty sub is
// refused even for a public client, whose sub would otherwise come back
// unchanged as an empty "user", and a hint that isn't an ID token this
// server issued is refused before any lookup.
func TestResolveClientSubjectRefusesEmptyAndInvalidInput(t *testing.T) {
	public := newHarness(t, server.ProfileFAPISecurity, true)
	if got, err := public.server.ResolveClientSubject(context.Background(), testClientID, ""); serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Errorf("an empty sub at a public client: %q, %v; want invalid_request", got, err)
	}
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), newMappingDeriver())
	if _, err := h.server.ResolveClientSubject(context.Background(), testClientID, ""); serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Errorf("an empty sub: %v, want invalid_request", err)
	}
	if _, err := h.server.ResolveIDTokenHint(context.Background(), "not-an-id-token", testClientID); serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Errorf("an invalid hint: %v, want invalid_request", err)
	}
}

// TestSignUserInfoResponseChecksPairwiseSubShape: for a pairwise client,
// a sub with the prefix but a malformed body is refused; and under
// SubjectTypesPairwiseOnly, a client still registered as public is
// refused outright rather than signed for.
func TestSignUserInfoResponseChecksPairwiseSubShape(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	h.cfg.Algorithms.UserInfo = fapi.ES256
	h = withPairwise(t, h, pairwiseClient(false), hmacDeriver(t))
	client, err := h.clients.ResolveClient(context.Background(), testClientID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(testPairwisePrefix + "not a body!")
	if _, err := h.server.SignUserInfoResponse(context.Background(), client, map[string]json.RawMessage{"sub": raw}); err == nil {
		t.Error("a malformed pairwise body was signed, want it refused")
	}

	public := pairwiseClient(false)
	public.SubjectType = fapi.SubjectTypePublic
	register(t, h, public)
	h.cfg.Subjects.Default = fapi.SubjectTypePairwise
	h.cfg.Subjects.Enforcement = server.SubjectTypesPairwiseOnly
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client, err = h.clients.ResolveClient(context.Background(), testClientID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal("user-1")
	if _, err := srv.SignUserInfoResponse(context.Background(), client, map[string]json.RawMessage{"sub": raw}); err == nil {
		t.Error("a public client under SubjectTypesPairwiseOnly was signed for, want it refused")
	}
}

// TestPairwiseExplicitSectorMatchesDerived: a Sector set as "RP.example"
// names the same host a client with redirect URIs at rp.example derives,
// so both clients' users get the same pairwise sub, as OpenID Connect
// Core §8.1 makes one sector one sub.
func TestPairwiseExplicitSectorMatchesDerived(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), hmacDeriver(t))
	upper := pairwiseClient(false)
	upper.ID = "upper-sector-client"
	upper.Sector = "RP.example"
	register(t, h, upper)
	explicit, err := h.server.ClientSubject(context.Background(), upper.ID, mustAuthenticated(t, "user-1"))
	if err != nil {
		t.Fatal(err)
	}
	if derived := clientSubjectOf(t, h, "user-1"); explicit != derived {
		t.Errorf("Sector RP.example gives %q, the derived rp.example %q; want the same sub", explicit, derived)
	}
}

// TestSignUserInfoResponseWithAnEmptyPrefix: with an empty prefix
// (allowed for a reversible deriver) nothing distinguishes a pairwise
// sub from an internal subject but a lookup, so a sub that doesn't map
// back under the client's sector, the internal subject included, is
// refused.
func TestSignUserInfoResponseWithAnEmptyPrefix(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	h.cfg.Algorithms.UserInfo = fapi.ES256
	h = withPairwise(t, h, pairwiseClient(false), newMappingDeriver())
	h.cfg.Subjects.Prefix = mustPrefix(t, "")
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	h.server = srv
	client, err := h.clients.ResolveClient(context.Background(), testClientID)
	if err != nil {
		t.Fatal(err)
	}
	for sub, wantRefused := range map[string]bool{
		clientSubjectOf(t, h, "user-1"): false,
		"user-1":                        true,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": true,
	} {
		raw, _ := json.Marshal(sub)
		if _, serr := h.server.SignUserInfoResponse(context.Background(), client, map[string]json.RawMessage{"sub": raw}); (serr != nil) != wantRefused {
			t.Errorf("sub %q: refused = %v (%v), want %v", sub, serr != nil, serr, wantRefused)
		}
	}
}

// TestSignUserInfoResponseAfterASectorChange: a grant keeps the sub it
// was issued with when its client's sector changes, so a signed UserInfo
// response for that grant still carries it.
func TestSignUserInfoResponseAfterASectorChange(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	h.cfg.Algorithms.UserInfo = fapi.ES256
	h = withPairwise(t, h, pairwiseClient(false), reversiblePairwise(t))
	before := clientSubjectOf(t, h, "user-1")
	moved := pairwiseClient(false)
	moved.Sector = "moved.example"
	register(t, h, moved)
	client, err := h.clients.ResolveClient(context.Background(), testClientID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(before)
	if _, serr := h.server.SignUserInfoResponse(context.Background(), client, map[string]json.RawMessage{"sub": raw}); serr != nil {
		t.Errorf("SignUserInfoResponse with the grant's earlier-sector sub: %v", serr)
	}
}
