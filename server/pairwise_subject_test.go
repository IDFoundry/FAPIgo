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
// deriver under derivation.
func withPairwise(t *testing.T, h harness, client storage.RegisteredClientConfig, derivation pairwise.Derivation, deriver pairwise.Deriver) harness {
	t.Helper()
	register(t, h, client)
	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePublic, Enforcement: server.SubjectTypesPerClient,
		Derivation: derivation, Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = deriver
	if derivation == pairwise.OneWay {
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
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, hmacDeriver(t))
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
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), public, pairwise.OneWay, hmacDeriver(t))
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
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, hmacDeriver(t))
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
// a grant keeps the sub it was issued with when the subject
// configuration later changes (here the prefix), so its refreshed ID
// tokens keep it too (OIDC Core §12.2); a new authorization gets the new
// sub.
func TestPairwiseSubjectSurvivesConfigurationChange(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, hmacDeriver(t))
	before := clientSubjectOf(t, h, "user-1")
	first, _ := exchangeForTokensWithOfflineAccess(t, h)

	h.cfg.Subjects.Prefix = mustPrefix(t, "changed:")
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	after := clientSubjectOf(t, h, "user-1")
	if after == before {
		t.Fatalf("ClientSubject is %q under both prefixes", after)
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

// TestLegacyGrantKeepsItsSubject: a grant record written before
// client_sub existed issues the internal subject, as it always did.
func TestLegacyGrantKeepsItsSubject(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, hmacDeriver(t))
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
// pairwise.OneWay the interaction shows that sub (compare it with
// ClientSubject); with a lookup, the user's own subject.
func TestPairwiseRequiredSubject(t *testing.T) {
	for _, tc := range []struct {
		name       string
		derivation pairwise.Derivation
		deriver    func(t *testing.T) pairwise.Deriver
		hint       bool
		user       string
		wantError  string
	}{
		{name: "one-way, hint, same user", derivation: pairwise.OneWay, deriver: hmacDeriver, hint: true, user: "user-1"},
		{name: "one-way, hint, different user", derivation: pairwise.OneWay, deriver: hmacDeriver, hint: true, user: "user-2", wantError: "login_required"},
		{name: "one-way, sub value, different user", derivation: pairwise.OneWay, deriver: hmacDeriver, user: "user-2", wantError: "login_required"},
		{name: "reversible, hint, same user", derivation: pairwise.Reversible, deriver: func(*testing.T) pairwise.Deriver { return newMappingDeriver() }, hint: true, user: "user-1"},
		{name: "reversible, sub value, different user", derivation: pairwise.Reversible, deriver: func(*testing.T) pairwise.Deriver { return newMappingDeriver() }, user: "user-2", wantError: "login_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), tc.derivation, tc.deriver(t))
			sub := clientSubjectOf(t, h, "user-1")
			extra := map[string]string{"claims": subClaims("id_token", sub)}
			if tc.hint {
				extra = map[string]string{"id_token_hint": serverHint(t, h, func(c map[string]any) { c["sub"] = sub })}
			}
			required := interactionFor(t, h, extra)
			wantShown := sub
			if tc.derivation == pairwise.Reversible {
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
			h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.Reversible, newMappingDeriver())
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
// under pairwise.OneWay; a "claims" sub value is enforced either way.
func TestPairwiseCIBA(t *testing.T) {
	t.Run("ID token sub", func(t *testing.T) {
		h := cibaWithPairwise(t, pairwise.OneWay, hmacDeriver(t))
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
		h := cibaWithPairwise(t, pairwise.OneWay, hmacDeriver(t))
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
		h := cibaWithPairwise(t, pairwise.OneWay, hmacDeriver(t))
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
			h := cibaWithPairwise(t, pairwise.Reversible, newMappingDeriver())
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
func cibaWithPairwise(t *testing.T, derivation pairwise.Derivation, deriver pairwise.Deriver) harness {
	t.Helper()
	h, _ := newHarnessWithBackchannel(t)
	return withPairwise(t, h, pairwiseClient(true), derivation, deriver)
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
// derived gets no code, never one for the internal subject: a deriver
// failing, a pairwise-only server with a client registered public, and a
// pairwise client of a server without a deriver.
func TestPairwiseSubjectFailsClosed(t *testing.T) {
	t.Run("deriver fails", func(t *testing.T) {
		h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, failingDeriver{hmacDeriver(t)})
		assertCompletionServerError(t, h)
	})
	t.Run("public client under pairwise only", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		public := pairwiseClient(false)
		public.SubjectType = fapi.SubjectTypePublic
		register(t, h, public)
		h.cfg.Subjects = server.SubjectConfig{
			Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPairwiseOnly,
			Derivation: pairwise.OneWay, Prefix: mustPrefix(t, testPairwisePrefix),
		}
		h.deps.PairwiseSubjects = hmacDeriver(t)
		h.deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
		srv, err := server.New(h.cfg, h.deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		h.server = srv
		assertCompletionServerError(t, h)
	})
	t.Run("no deriver", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		register(t, h, pairwiseClient(false))
		srv, err := server.New(h.cfg, h.deps)
		if err != nil {
			t.Fatalf("server.New: %v", err)
		}
		h.server = srv
		assertCompletionServerError(t, h)
	})
}

// failingDeriver derives the fixed input New probes with, and fails for
// every other.
type failingDeriver struct{ pairwise.Deriver }

func (f failingDeriver) DerivePairwiseSubject(ctx context.Context, in pairwise.Input) (string, error) {
	if in.Subject() == "fapigo-pairwise-probe" {
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
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, hmacDeriver(t))
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
		Derivation: pairwise.OneWay, Prefix: mustPrefix(t, testPairwisePrefix),
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

			h.cfg.Subjects = server.SubjectConfig{
				Default: fapi.SubjectTypePairwise, Enforcement: tc.enforcement,
				Derivation: pairwise.Reversible, Prefix: mustPrefix(t, testPairwisePrefix),
			}
			h.deps.PairwiseSubjects = newMappingDeriver()
			srv, err := server.New(h.cfg, h.deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			h.server = srv

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

// TestSignUserInfoResponseRefusesInternalSubForPairwiseClient: a signed
// UserInfo response for a pairwise client must carry the sub the client
// was given, not the user's internal subject, which an embedder still
// copying AuthorizationContext.Subject would otherwise hand over. A
// public client's sub isn't checked.
func TestSignUserInfoResponseRefusesInternalSubForPairwiseClient(t *testing.T) {
	for name, tc := range map[string]struct {
		derivation pairwise.Derivation
		deriver    pairwise.Deriver
	}{
		"one-way":    {pairwise.OneWay, hmacDeriver(t)},
		"reversible": {pairwise.Reversible, newMappingDeriver()},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			h.cfg.Algorithms.UserInfo = fapi.ES256
			h = withPairwise(t, h, pairwiseClient(false), tc.derivation, tc.deriver)
			client, err := h.clients.ResolveClient(context.Background(), testClientID)
			if err != nil {
				t.Fatal(err)
			}
			clientSub := clientSubjectOf(t, h, "user-1")
			for sub, wantRefused := range map[string]bool{
				clientSub: false,
				"user-1":  true, // the internal subject
				testPairwisePrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": tc.derivation == pairwise.Reversible, // well-formed, never issued
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
