package linked

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const (
	callbackPath  = "/callback"
	sessionCookie = "pocketwise_session"
)

// linkScope is what Pocketwise asks for: the account information API,
// and offline_access for a refresh token to sync with later.
var linkScope = []string{"openid", "accounts", "offline_access"}

// pocketwise is Pocketwise: it links a customer's accounts once, then
// syncs them on its own with its refresh token.
type pocketwise struct {
	w        *World
	keys     *rotatingDPoPKeys
	sessions storage.SessionStore
	// client is Pocketwise's FAPIgo client. thriftly is Thriftly's: a
	// different app, with its own valid credentials and DPoP key.
	client, thriftly *lazyClient

	mu       sync.Mutex
	link     *link
	log      []syncEntry
	attempts []attempt
	trace    *trace
}

// link is Pocketwise's connection to the customer's accounts: the
// tokens the link and its last sync left it with.
type link struct {
	tokens   client.TokenSet
	linkedAt time.Time
	// Accounts is what the last successful sync returned.
	Accounts []accountView
}

// syncEntry is one line of the sync log.
type syncEntry struct {
	When, What, Result string
	OK                 bool
}

type attempt struct {
	Title, Result string
	Refused       bool
}

func (w *World) newPocketwise(apps apps) *pocketwise {
	p := &pocketwise{
		w: w, keys: &rotatingDPoPKeys{base: apps.pocketwise.keys}, sessions: memstore.NewSessionStore(), trace: &trace{},
	}
	p.client = &lazyClient{w: w, clientID: pocketwiseClientID, keys: p.keys, redirect: w.URL(pocketwiseHost, callbackPath), sessions: p.sessions}
	p.thriftly = &lazyClient{w: w, clientID: thriftlyClientID, keys: apps.thriftly.keys, redirect: string(apps.thriftly.redirectURI(w)), sessions: memstore.NewSessionStore()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.home)
	mux.HandleFunc("GET "+callbackPath, p.callback)
	protect := http.NewCrossOriginProtection()
	for path, h := range map[string]http.HandlerFunc{"/link": p.start, "/sync": p.syncNow, "/rotate-key": p.rotateKey, "/attack": p.attack} {
		mux.Handle("POST "+path, protect.Handler(h))
	}
	w.router[pocketwiseHost] = mux
	return p
}

// lazyClient is a FAPIgo client built from Alder Bank's published
// metadata the first time it's needed (the bank isn't listening yet when
// the demo starts).
type lazyClient struct {
	w        *World
	clientID fapi.ClientID
	keys     keys.KeyManager
	redirect string
	sessions storage.SessionStore

	mu sync.Mutex
	c  *client.Client
}

func (l *lazyClient) get(ctx context.Context) (*client.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c != nil {
		return l.c, nil
	}
	fetcher, err := l.w.fetcher(pocketwiseHost)
	if err != nil {
		return nil, err
	}
	issuer, err := fapi.ParseIssuerURL(l.w.URL(bankHost, ""))
	if err != nil {
		return nil, err
	}
	discovered, err := client.Discover(ctx, fetcher, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover Alder Bank: %w", err)
	}
	issuerKeys, err := discovered.IssuerKeySource(fetcher, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	limits := client.RecommendedLimits()
	limits.MaxIDTokenLifetime = 10 * time.Minute // Alder Bank's (server.RecommendedLimits)
	c, err := client.NewFromDiscovery(discovered, client.Config{
		ClientID: l.clientID, RedirectURI: l.redirect,
		Profile: client.ProfileFAPISecurity, Assurance: client.AssuranceDevelopment,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		Algorithms:                     client.Algorithms{ClientAuthentication: fapi.ES256, DPoP: fapi.ES256, IDToken: fapi.ES256},
		Limits:                         limits,
		SenderConstrain:                storage.SenderConstrainDPoP,
		ClientAuthMethod:               storage.ClientAuthMethodPrivateKeyJWT,
	}, client.Dependencies{
		Sessions: l.sessions, Keys: l.keys, IssuerKeys: issuerKeys,
		HTTP: tracingClient{next: l.w.net.Client(pocketwiseHost)},
		// The demo clock, so fast-forwarding moves Pocketwise's own checks
		// (token and proof lifetimes) along with the bank's.
		Clock: l.w.clock, Random: rand.Reader,
	})
	if err != nil {
		return nil, err
	}
	l.c = c
	return c, nil
}

func (p *pocketwise) ctx(ctx context.Context) context.Context { return withTrace(ctx, p.trace) }

// start links the customer's accounts: a pushed authorization request
// for offline_access and account_access, naming no accounts, so the
// customer chooses at the bank.
func (p *pocketwise) start(w http.ResponseWriter, r *http.Request) {
	c, err := p.client.get(r.Context())
	if err != nil {
		p.fail(w, r, "link", err)
		return
	}
	detail, err := extension.RARSet(accountAccessType, accountAccess{Actions: []string{"read_balances", "read_transactions"}})
	if err != nil {
		p.fail(w, r, "link", err)
		return
	}
	session, err := c.BeginAuthorization(p.ctx(r.Context()), client.BeginAuthorizationRequest{
		Scope: linkScope, AuthorizationDetails: []json.RawMessage{detail},
	})
	if err != nil {
		p.fail(w, r, "link", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session.Handle().String(), Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	u := session.URL()
	// Not an open redirect: Alder Bank's authorization endpoint, from its
	// discovery metadata.
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: see above
}

// callback finishes linking: the code for tokens, including the refresh
// token, then a first sync.
func (p *pocketwise) callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		p.w.renderError(w, pocketwiseHost, http.StatusBadRequest, "No link in progress", "This browser didn't start linking here.")
		return
	}
	handle, err := client.ParseSessionHandle(cookie.Value)
	if err != nil {
		p.w.renderError(w, pocketwiseHost, http.StatusBadRequest, "No link in progress", notStartedHere)
		return
	}
	ctx := p.ctx(r.Context())
	c, err := p.client.get(ctx)
	if err != nil {
		p.fail(w, r, "link", err)
		return
	}
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: r.URL.RawQuery, Session: handle})
	if err != nil {
		p.fail(w, r, "link", err)
		return
	}
	switch res := result.(type) {
	case client.CompletionDenied:
		p.record("Link accounts", "Alder Bank answered "+res.Code+": "+res.Description, false)
	case client.CompletionSuccess:
		p.mu.Lock()
		p.link = &link{tokens: res.Tokens, linkedAt: p.w.clock.Now()}
		p.mu.Unlock()
		p.record("Link accounts", "Linked, with a refresh token valid for 90 days", true)
		p.fetchAccounts(ctx, res.Tokens, "First sync")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// syncNow is a background sync: no browser, no customer. The refresh
// token buys a fresh access token, which reads the shared accounts.
func (p *pocketwise) syncNow(w http.ResponseWriter, r *http.Request) {
	p.sync(p.ctx(r.Context()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *pocketwise) sync(ctx context.Context) {
	p.mu.Lock()
	l := p.link
	p.mu.Unlock()
	if l == nil {
		p.record("Sync", "Nothing linked yet", false)
		return
	}
	c, err := p.client.get(ctx)
	if err != nil {
		p.record("Sync", err.Error(), false)
		return
	}
	refreshed, err := c.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: l.tokens})
	if err != nil {
		p.record("Sync: refresh", describeError(err), false)
		// The access token from before is all Pocketwise has left.
		p.fetchAccounts(ctx, l.tokens, "Sync: the last access token")
		return
	}
	p.mu.Lock()
	l.tokens = refreshed
	p.mu.Unlock()
	p.record("Sync: refresh", "New access token; the same refresh token, not rotated (FAPI 2.0)", true)
	p.fetchAccounts(ctx, refreshed, "Sync: read accounts")
}

// fetchAccounts reads the shared accounts with tokens' access token.
func (p *pocketwise) fetchAccounts(ctx context.Context, tokens client.TokenSet, what string) {
	accounts, status, err := p.callAPI(ctx, p.client, tokens)
	if err != nil {
		p.record(what, err.Error(), false)
		return
	}
	if status != "" {
		p.record(what, status, false)
		return
	}
	names := make([]string, len(accounts))
	for i, a := range accounts {
		names[i] = a.Name
	}
	p.mu.Lock()
	if p.link != nil {
		p.link.Accounts = accounts
	}
	p.mu.Unlock()
	p.record(what, "Read "+strings.Join(names, ", "), true)
}

// callAPI reads the account information API through lc with tokens'
// access token, returning the accounts, or the API's refusal.
func (p *pocketwise) callAPI(ctx context.Context, lc *lazyClient, tokens client.TokenSet) ([]accountView, string, error) {
	c, err := lc.get(ctx)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.w.URL(apiHost, accountsPath), nil)
	if err != nil {
		return nil, "", err
	}
	res, err := c.ProtectedResource(tokens).Do(ctx, req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("%s %s", res.Status, strings.TrimSpace(res.Header.Get("WWW-Authenticate")+" "+string(body))), nil
	}
	var accounts []accountView
	if err := json.Unmarshal(body, &accounts); err != nil {
		return nil, "", err
	}
	return accounts, "", nil
}

// rotateKey replaces Pocketwise's DPoP key: allowed for a confidential
// client, and the next refresh binds its access token to the new key.
func (p *pocketwise) rotateKey(w http.ResponseWriter, r *http.Request) {
	if err := p.keys.rotate(); err != nil {
		p.record("Rotate DPoP key", err.Error(), false)
	} else {
		p.record("Rotate DPoP key", "New DPoP key; the next sync's access token is bound to it", true)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *pocketwise) record(what, result string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log = append([]syncEntry{{When: p.w.clock.Now().Format("2 Jan 2006 15:04"), What: what, Result: result, OK: ok}}, p.log...)
}

func (p *pocketwise) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.record(what, describeError(err), false)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *pocketwise) home(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	page := pocketwisePage{
		Page: p.w.page("Pocketwise", pocketwiseHost), Log: append([]syncEntry(nil), p.log...),
		Attempts: append([]attempt(nil), p.attempts...), Trace: p.trace.Steps(),
	}
	if p.link != nil {
		page.Linked, page.Accounts = true, p.link.Accounts
		page.LinkedAt = p.link.linkedAt.Format("2 Jan 2006")
	}
	p.mu.Unlock()
	p.w.render(w, "pocketwise", page)
}

// attack misuses the link's long-lived access.
func (p *pocketwise) attack(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	l := p.link
	p.mu.Unlock()
	if l == nil {
		p.w.renderError(w, pocketwiseHost, http.StatusBadRequest, "Nothing linked", "Link accounts first: the attacks use the link's tokens.")
		return
	}
	ctx := withTrace(r.Context(), &trace{}) // not the link's trace
	var a attempt
	switch r.FormValue("kind") {
	case "thriftly":
		a = p.refreshAttempt(ctx, "Redeem Pocketwise's refresh token as Thriftly", p.thriftly, l.tokens, nil)
	case "no-client-auth":
		a = p.refreshWithoutClientAuthentication(ctx, l.tokens)
	case "widen":
		a = p.refreshAttempt(ctx, "Refresh asking for a scope that was never granted", p.client, l.tokens, []string{"openid", "accounts", "offline_access", "payments"})
	case "other-key":
		a = attempt{Title: "Use Pocketwise's access token with another app's DPoP key"}
		accounts, status, err := p.callAPI(ctx, p.thriftly, l.tokens)
		switch {
		case err != nil:
			a.Refused, a.Result = true, err.Error()
		case status != "":
			a.Refused, a.Result = true, status
		default:
			a.Result = fmt.Sprintf("accepted: read %d accounts", len(accounts))
		}
	default:
		p.w.renderError(w, pocketwiseHost, http.StatusBadRequest, "Unknown attack", r.FormValue("kind"))
		return
	}
	p.mu.Lock()
	p.attempts = append([]attempt{a}, p.attempts...)
	p.mu.Unlock()
	http.Redirect(w, r, "/#attempts", http.StatusSeeOther)
}

func (p *pocketwise) refreshAttempt(ctx context.Context, title string, lc *lazyClient, tokens client.TokenSet, scope []string) attempt {
	c, err := lc.get(ctx)
	if err == nil {
		_, err = c.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens, Scope: scope})
	}
	if err != nil {
		return attempt{Title: title, Result: describeError(err), Refused: true}
	}
	return attempt{Title: title, Result: "accepted: a new access token was issued"}
}

// refreshWithoutClientAuthentication presents the refresh token to the
// token endpoint with only a client_id: no client assertion.
func (p *pocketwise) refreshWithoutClientAuthentication(ctx context.Context, tokens client.TokenSet) attempt {
	a := attempt{Title: "Redeem the refresh token without authenticating as Pocketwise"}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken.Reveal()}, "client_id": {string(pocketwiseClientID)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.w.URL(bankHost, "/token"), strings.NewReader(form.Encode()))
	if err != nil {
		return attempt{Title: a.Title, Result: err.Error(), Refused: true}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := p.w.net.Client("attacker").Do(req)
	if err != nil {
		return attempt{Title: a.Title, Result: err.Error(), Refused: true}
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	a.Refused, a.Result = res.StatusCode != http.StatusOK, res.Status+"\n"+prettyJSON(body)
	return a
}

// describeError is err as a page shows it: the bank's OAuth error, when
// there is one.
func describeError(err error) string {
	var ce *client.Error
	if errors.As(err, &ce) {
		if resp, ok := ce.ServerResponse(); ok && resp.Description != "" {
			return fmt.Sprintf("%s: %s", resp.Code, resp.Description)
		}
	}
	return err.Error()
}
