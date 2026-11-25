package sqlstore_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// Races between calls of server.Server's own API, on a server whose
// stores are all this package's, on SQLite and on PostgreSQL: concurrent
// exchanges of one authorization code, a grant revocation racing a
// refresh, and concurrent begins and completions of one request_uri's
// interactions (and, in server_ciba_race_test.go, a CIBA request's
// decisions racing its polls). Each test checks what must hold once
// every call has returned, whatever order the store serialized them in,
// never how long anything took.

// serverRaceCallers is how many calls a race below makes at once.
const serverRaceCallers = 8

// serverRaceIterations is how many races each test below runs on each
// database.
const serverRaceIterations = 10

// serverRace is a place, a migrated handle on it with the flow's client
// registered, and a server over it (flowDeployment's, unless a test
// builds its own), with a resource server's verifier of the server's
// access tokens.
type serverRace struct {
	t        *testing.T
	p        *place
	d        *sqlstore.DB
	app      flowClient
	cfg      server.Config
	deps     server.Dependencies
	srv      *server.Server
	verifier *resource.Verifier
}

// newServerRace is a serverRace on dialect with grants (of d) as the
// server's GrantStore, and noRevocation for server.NoRevocation as its
// Revocation, in which only the registry's revocation of a refresh token
// ends a grant.
func newServerRace(t *testing.T, dialect sqlstore.Dialect, grants func(*sqlstore.DB) storage.GrantStore, noRevocation bool) *serverRace {
	t.Helper()
	p := newPlace(t, dialect)
	d := p.migrated()
	r := &serverRace{t: t, p: p, d: d, app: newFlowClient(t, d)}
	r.cfg, r.deps = flowDeployment(t, d, grants(d), server.SystemClock{})
	if noRevocation {
		r.deps.Revocation = server.NoRevocation{}
	}
	srv, err := server.New(r.cfg, r.deps)
	must(t, err)
	r.srv = srv
	// The resource server's DPoP nonces are its own (NewVerifier refuses
	// the server's): another prefix, in the same SQLite file.
	nonces := newPlace(t, dialect)
	nonces.path = p.path
	r.verifier, err = serverresource.NewVerifier(r.cfg, r.deps, serverresource.Options{
		ResourceURLs: []fapi.URL{mustURL(t, "https://as.example/userinfo")}, Nonces: nonces.migrated().Nonces(),
	})
	must(t, err)
	return r
}

// grantStores are the GrantStores a server can have of a DB.
var grantStores = map[string]func(*sqlstore.DB) storage.GrantStore{
	"Grants":         func(d *sqlstore.DB) storage.GrantStore { return d.Grants() },
	"BatchingGrants": func(d *sqlstore.DB) storage.GrantStore { return d.BatchingGrants() },
}

// exchange redeems code on r's server, returning what it issued.
func (r *serverRace) exchange(code string) (server.TokenResult, error) {
	return r.srv.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: form("client_id", string(flowClientID), "grant_type", "authorization_code", "code", code,
			"redirect_uri", flowRedirect, "code_verifier", flowVerifier),
		PeerCertificate: r.app.cert,
	})
}

// refresh redeems refreshToken on r's server, returning what it issued.
func (r *serverRace) refresh(refreshToken string) (server.TokenResult, error) {
	return r.srv.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:            form("client_id", string(flowClientID), "grant_type", "refresh_token", "refresh_token", refreshToken),
		PeerCertificate: r.app.cert,
	})
}

// verify presents accessToken to r's resource server, with the client's
// certificate, returning the verifier's error.
func (r *serverRace) verify(accessToken string) error {
	_, err := r.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: &url.URL{Scheme: "https", Host: "as.example", Path: "/userinfo"},
		Authorization: "Bearer " + accessToken, PeerCertificate: r.app.cert,
	})
	return err
}

// tokens is the first exchange of a new code on r's server, which must
// issue a refresh token.
func (r *serverRace) tokens(grantID string) server.TokenResult {
	r.t.Helper()
	issued, err := r.exchange(r.app.code(context.Background(), r.srv, time.Now(), grantID))
	must(r.t, err)
	if !issued.HasRefreshToken {
		r.t.Fatal("the code exchange issued no refresh token")
	}
	return issued
}

// wantRefused fails r's test unless issued's access token is refused by
// the resource server and its refresh token by the server.
func (r *serverRace) wantRefused(what string, issued server.TokenResult) {
	r.t.Helper()
	if err := r.verify(issued.AccessToken.Reveal()); err == nil {
		r.t.Errorf("%s: the resource server accepted the access token", what)
	}
	if _, err := r.refresh(issued.RefreshToken.Reveal()); !isInvalidGrant(err) {
		r.t.Errorf("%s: refresh with the refresh token = %v, want invalid_grant", what, err)
	}
}

// --- Concurrent exchanges of one authorization code ------------------

// isRevokedWhileIssued reports whether err is a token request refused
// because its grant was revoked while its refresh token was being
// stored: invalid_grant, "the grant has been revoked". FAPIgo before
// v0.86.0 answered server_error instead, in one of two forms, depending
// on which of the server's two checks after storing the token saw the
// revocation (the check that the grant isn't revoked: its cause is the
// invalid_grant that check found; the check that the grant registry
// still lists the grant: its cause is the server's "revoked while its
// refresh token was being issued" error, matched by its text). Those
// forms are accepted only when these tests are built against a released
// FAPIgo (fapigoFromTree): CI also runs them against the release this
// module's go.mod requires, which may predate v0.86.0. Built against the
// tree beside it, as they are otherwise, only invalid_grant is.
func isRevokedWhileIssued(err error) bool {
	var outer *server.Error
	if !errors.As(err, &outer) {
		return false
	}
	if outer.Code() == server.ErrorInvalidGrant {
		return outer.PublicDescription() == "the grant has been revoked"
	}
	if fapigoFromTree || outer.Code() != server.ErrorServerError {
		return false
	}
	cause := errors.Unwrap(outer)
	var inner *server.Error
	if errors.As(cause, &inner) && inner.Code() == server.ErrorInvalidGrant {
		return true
	}
	return cause != nil && cause.Error() == "the grant was revoked while its refresh token was being issued"
}

// fapigoFromTree reports whether this module's go.mod replaces FAPIgo
// with the tree beside it, so these tests are built against that tree,
// not a released version (CI's run against the release drops the
// replace with go mod edit). A test binary carries no build info about
// its dependencies, so go.mod is read instead.
var fapigoFromTree = func() bool {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		return false
	}
	for line := range strings.Lines(string(mod)) {
		if strings.HasPrefix(strings.TrimSpace(line), "replace github.com/idfoundry/fapigo =>") {
			return true
		}
	}
	return false
}()

// Concurrent exchanges of one authorization code: at most one issues
// tokens and every other is invalid_grant, and the others' reuse of the
// code revokes what the one issued (RFC 6749 §4.1.2) — its access token
// at the resource server and its refresh token at the server — however
// the reuse and the issuance interleave. None may issue: the exchange
// that redeemed the code stores its refresh token and then confirms the
// code's grant isn't revoked, and a reuse may have revoked it by then,
// so it withdraws the token and is invalid_grant too
// (isRevokedWhileIssued).
func TestServerConcurrentCodeExchanges(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for name, grants := range grantStores {
			t.Run(name, func(t *testing.T) {
				r := newServerRace(t, dialect, grants, false)
				r.checkUnracedExchangeIsLive()
				var won, withdrawn int
				for range serverRaceIterations {
					out := r.raceCodeExchanges()
					won += out.won
					withdrawn += out.withdrawn
					r.checkCodeExchanges(out, isInvalidGrant, isRevokedWhileIssued)
				}
				t.Logf("%s: %d races: %d exchanges issued tokens, %d were refused as their grant was revoked while they issued", dialect, serverRaceIterations, won, withdrawn)
			})
		}
	})
}

// When a reuse of an authorization code revokes its grant while the
// exchange that redeemed it is storing its refresh token, that exchange
// issues nothing and answers invalid_grant (400), the grant refused, not
// the server_error (500) of a store failure: every loser of the race is
// invalid_grant. (Against a FAPIgo release before v0.86.0, which
// answered server_error, isRevokedWhileIssued accepts that too.)
func TestServerCodeReuseRacingIssuanceIsInvalidGrant(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		r := newServerRace(t, dialect, grantStores["Grants"], false)
		for range serverRaceIterations {
			r.checkCodeExchanges(r.raceCodeExchanges(), isInvalidGrant, isRevokedWhileIssued)
		}
	})
}

// checkUnracedExchangeIsLive checks the tokens of a code exchanged once
// are accepted, so that a refusal after a race is the race's doing, and
// that a later reuse of the code, unraced, revokes them.
func (r *serverRace) checkUnracedExchangeIsLive() {
	r.t.Helper()
	code := r.app.code(context.Background(), r.srv, time.Now(), "")
	issued, err := r.exchange(code)
	must(r.t, err)
	if err := r.verify(issued.AccessToken.Reveal()); err != nil {
		r.t.Fatalf("setup: the resource server refused an unraced exchange's access token: %v", err)
	}
	if _, err := r.refresh(issued.RefreshToken.Reveal()); err != nil {
		r.t.Fatalf("setup: refresh with an unraced exchange's refresh token: %v", err)
	}
	if _, err := r.exchange(code); !isInvalidGrant(err) {
		r.t.Fatalf("an unraced reuse of the code = %v, want invalid_grant", err)
	}
	r.wantRefused("an unraced exchange's tokens after the code's reuse", issued)
}

// codeExchanges are what a race of exchanges of one code returned, and
// how many issued tokens or were refused by isRevokedWhileIssued.
type codeExchanges struct {
	results        []server.TokenResult
	errs           []error
	won, withdrawn int
}

// raceCodeExchanges runs one race of serverRaceCallers exchanges of one
// code.
func (r *serverRace) raceCodeExchanges() codeExchanges {
	r.t.Helper()
	code := r.app.code(context.Background(), r.srv, time.Now(), "")
	out := codeExchanges{results: make([]server.TokenResult, serverRaceCallers), errs: make([]error, serverRaceCallers)}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range serverRaceCallers {
		wg.Go(func() {
			<-start
			out.results[i], out.errs[i] = r.exchange(code)
		})
	}
	close(start)
	wg.Wait()
	for _, err := range out.errs {
		out.won += oneIf(err == nil)
		out.withdrawn += oneIf(isRevokedWhileIssued(err))
	}
	return out
}

// checkCodeExchanges checks that at most one of out's exchanges issued
// tokens, now refused, and that every other lost as one of lost says.
func (r *serverRace) checkCodeExchanges(out codeExchanges, lost ...func(error) bool) {
	r.t.Helper()
	if out.won > 1 {
		r.t.Errorf("%d of %d concurrent exchanges of one code issued tokens, want at most 1", out.won, len(out.errs))
	}
	for i, err := range out.errs {
		switch {
		case err == nil:
			r.wantRefused("the winning exchange's tokens after the code's reuse", out.results[i])
		case !anyOf(err, lost):
			r.t.Errorf("a concurrent exchange of one code = %v, want a loser's outcome", err)
		}
	}
}

// anyOf reports whether one of preds holds for err.
func anyOf(err error, preds []func(error) bool) bool {
	for _, pred := range preds {
		if pred(err) {
			return true
		}
	}
	return false
}

// --- A grant revocation racing a refresh -------------------------------

// RevokeSubjectGrants or RevokeListedGrant racing a refresh of the
// grant's refresh token (RefreshAccessToken, which issues an access
// token and returns the refresh token unrotated): the revocation finds
// and revokes the grant, and once both have returned the refresh token
// is refused, and so, with grant revocation (a Revocation store), is the
// access token the refresh issued if it won. Without one (registry
// only), an access token is good until it expires, by design. The
// store keeps no live refresh token row, and the subject has no grant
// left to revoke. (registry_race_test.go races the same revocations
// against a code exchange's storing of a new refresh token.)
func TestServerRevocationRacingRefresh(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for _, revocation := range []string{"Revocation", "RegistryOnly"} {
			for name, revoke := range subjectRevocations {
				t.Run(revocation+"/"+name, func(t *testing.T) {
					r := newServerRace(t, dialect, grantStores["Grants"], revocation == "RegistryOnly")
					var refreshed int
					for i := range serverRaceIterations {
						refreshed += oneIf(r.raceRefreshAndRevocation(i, revocation == "Revocation", revoke))
					}
					t.Logf("%s: %d races, %d refreshes won", dialect, serverRaceIterations, refreshed)
				})
			}
		}
	})
}

// raceRefreshAndRevocation runs one race of a refresh and revoke for a
// new grant on r's server, with a GrantID when grantRevocation, checks
// what it left, and reports whether the refresh issued an access token.
func (r *serverRace) raceRefreshAndRevocation(i int, grantRevocation bool, revoke func(context.Context, *server.Server, server.SubjectID) (int, error)) bool {
	r.t.Helper()
	grantID := ""
	if grantRevocation {
		grantID = "grant-" + string(rune('a'+i))
	}
	issued := r.tokens(grantID)
	var refreshed server.TokenResult
	var refreshErr, revokeErr error
	var revoked int
	subject := mustSubject(r.t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		refreshed, refreshErr = r.refresh(issued.RefreshToken.Reveal())
	})
	wg.Go(func() {
		<-start
		revoked, revokeErr = revoke(context.Background(), r.srv, subject)
	})
	close(start)
	wg.Wait()

	if revoked != 1 || revokeErr != nil {
		r.t.Errorf("revocation racing a refresh = %d, %v, want 1, nil", revoked, revokeErr)
	}
	if _, err := r.refresh(issued.RefreshToken.Reveal()); !isInvalidGrant(err) {
		r.t.Errorf("refresh with the grant's first refresh token after the revocation = %v, want invalid_grant", err)
	}
	switch {
	case refreshErr == nil && grantRevocation:
		if err := r.verify(refreshed.AccessToken.Reveal()); err == nil {
			r.t.Error("the resource server accepted the access token a refresh racing the revocation issued")
		}
	case refreshErr != nil && !isInvalidGrant(refreshErr):
		r.t.Errorf("refresh racing a revocation = %v, want success or invalid_grant", refreshErr)
	}
	checkNothingLeft(r.t, r.p, r.srv)
	return refreshErr == nil
}

// --- Concurrent begins and completions of one request_uri ---------------

// interactionsPerRequestURI is how many interactions BeginAuthorization
// lets one request_uri begin (its doc comment's
// maxInteractionsPerRequestURI).
const interactionsPerRequestURI = 8

// Concurrent BeginAuthorization calls for one request_uri begin exactly
// interactionsPerRequestURI interactions, refusing the rest with
// invalid_request_uri, and the bound holds through the replay store, not
// a lock in one process; concurrent CompleteAuthorization calls of those
// interactions, the same handle more than once and racing further
// begins, issue exactly one authorization code, which the client
// redeems once; and afterwards the request_uri begins nothing.
func TestServerConcurrentInteractions(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		r := newServerRace(t, dialect, grantStores["Grants"], false)
		for range serverRaceIterations {
			r.raceInteractions()
		}
	})
}

// interactionOutcomes are what a race of begins and completions of one
// request_uri's interactions returned.
type interactionOutcomes struct {
	mu      sync.Mutex
	handles []server.InteractionRequired
	refused int
	codes   []string
}

// raceInteractions runs one race of begins, then of completions and
// begins, of one request_uri on r's server, and checks what they
// returned.
func (r *serverRace) raceInteractions() {
	r.t.Helper()
	requestURI := r.app.push(context.Background(), r.srv)
	var out interactionOutcomes
	r.concurrentBegins(&out, requestURI, 2*interactionsPerRequestURI)
	if len(out.handles) != interactionsPerRequestURI || out.refused != interactionsPerRequestURI {
		r.t.Fatalf("%d concurrent begins of one request_uri: %d began and %d refused, want %d and %d",
			2*interactionsPerRequestURI, len(out.handles), out.refused, interactionsPerRequestURI, interactionsPerRequestURI)
	}

	// Every handle completed twice at once, alongside begins the bound
	// already refuses.
	handles := out.handles
	out = interactionOutcomes{}
	approval := r.approval()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, required := range append(handles, handles...) {
		wg.Go(func() {
			<-start
			r.complete(&out, required, approval)
		})
	}
	wg.Go(func() {
		<-start
		r.concurrentBegins(&out, requestURI, serverRaceCallers)
	})
	close(start)
	wg.Wait()
	if len(out.codes) != 1 || len(out.handles) != 0 {
		r.t.Fatalf("concurrent completions of one request_uri's interactions issued %d codes and began %d more, want 1 and 0", len(out.codes), len(out.handles))
	}
	if _, err := r.exchange(out.codes[0]); err != nil {
		r.t.Errorf("exchange of the one code the completions issued: %v", err)
	}
	out = interactionOutcomes{}
	r.concurrentBegins(&out, requestURI, 1)
	if len(out.handles) != 0 {
		r.t.Error("the request_uri began an interaction after one completed")
	}
}

// concurrentBegins runs n BeginAuthorization calls for requestURI at
// once, adding what they returned to out.
func (r *serverRace) concurrentBegins(out *interactionOutcomes, requestURI string, n int) {
	errs := concurrently(n, func() error {
		action, err := r.srv.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: requestURI, ClientID: flowClientID})
		if err != nil {
			return err
		}
		out.mu.Lock()
		defer out.mu.Unlock()
		switch a := action.(type) {
		case server.InteractionRequired:
			out.handles = append(out.handles, a)
		case server.LocalErrorResponse:
			if a.Error.Code() != server.ErrorInvalidRequestURI {
				return a.Error
			}
			out.refused++
		default:
			return errors.New("BeginAuthorization returned neither an interaction nor a local error")
		}
		return nil
	})
	for _, err := range errs {
		if err != nil {
			r.t.Errorf("a concurrent BeginAuthorization: %v", err)
		}
	}
}

// userApproval is the flow's end user, authenticated now.
type userApproval struct {
	subject server.AuthenticatedSubject
	authn   server.AuthenticationContext
}

// approval is the flow's end user, authenticated now.
func (r *serverRace) approval() userApproval {
	r.t.Helper()
	subject, err := server.NewAuthenticatedSubject(mustSubject(r.t))
	must(r.t, err)
	authn, err := server.NewAuthenticationContext(time.Now(), "acr-1", []string{"pwd"})
	must(r.t, err)
	return userApproval{subject: subject, authn: authn}
}

// complete completes required with approval, adding the code it issued,
// if any, to out. A completion that loses is a local error, never a
// redirect.
func (r *serverRace) complete(out *interactionOutcomes, required server.InteractionRequired, approval userApproval) {
	result, err := r.srv.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(approval.subject, approval.authn, server.GrantedAuthorization{Scope: required.Interaction.Scope}),
	})
	switch res := result.(type) {
	case nil:
		r.t.Errorf("a concurrent CompleteAuthorization: %v", err)
	case server.AuthorizationRedirect:
		destination := res.Destination().URL()
		code := destination.Query().Get("code")
		if code == "" {
			r.t.Errorf("a concurrent CompleteAuthorization redirected with no code: %v", destination.Query())
			return
		}
		out.mu.Lock()
		defer out.mu.Unlock()
		out.codes = append(out.codes, code)
	case server.AuthorizationLocalError:
		if res.Error.Code() == server.ErrorServerError {
			r.t.Errorf("a concurrent CompleteAuthorization: %v", res.Error)
		}
	default:
		r.t.Errorf("a concurrent CompleteAuthorization = %T", result)
	}
}
