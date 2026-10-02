package identity

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const (
	callbackPath  = "/callback"
	sessionCookie = "rp_session"
	checkCookie   = "rp_check"
)

// rpSetup is what a relying party asks Alder Bank for.
type rpSetup struct {
	name, host, purpose string
	clientID            fapi.ClientID
	// encrypt has the bank encrypt the ID token and UserInfo response to
	// this relying party.
	encrypt bool
	// idTokenClaims and userInfoClaims are what it requests with the
	// "claims" parameter, and where.
	idTokenClaims, userInfoClaims []string
	// acr, when set, is the authentication it requires (acr_values),
	// and maxAge, when hasMaxAge, how recent it must be (max_age).
	acr       string
	maxAge    time.Duration
	hasMaxAge bool
}

var fernwaySetup = rpSetup{
	name: "Fernway", host: fernwayHost, clientID: "fernway", encrypt: true,
	purpose:        "Open a Fernway savings account. We need to verify who you are: sign in with your bank instead of uploading a photo ID.",
	idTokenClaims:  []string{"given_name", "family_name", "birthdate"},
	userInfoClaims: []string{"address", "email", "phone_number"},
	acr:            acrApp, maxAge: 10 * time.Minute, hasMaxAge: true,
}

var brightlineSetup = rpSetup{
	name: "Brightline Rentals", host: brightlineHost, clientID: "brightline-rentals",
	purpose:        "Apply to rent a flat. Brightline checks your name and that you're over 18, and asks for your current address.",
	idTokenClaims:  []string{"given_name", "family_name", "birthdate"},
	userInfoClaims: []string{"address"},
}

// relyingParty is Fernway or Brightline Rentals: a client of Alder Bank's
// OpenID Provider that verifies who its customer is.
type relyingParty struct {
	w     *World
	setup rpSetup
	// keys signs this relying party's client assertions and DPoP proofs
	// and, for one that registered for encryption, decrypts what the bank
	// encrypts to it.
	keys     *ephemeral.KeyManager
	jwks     json.RawMessage
	sessions storage.SessionStore
	// client is the relying party's FAPIgo client. thief is the same
	// client software without its DPoP key: what someone who stole an
	// access token could do with it.
	client, thief *lazyClient

	mu     sync.Mutex
	checks map[string]*check
}

// check is one identity check.
type check struct {
	ID, Scenario string
	Status       string // redirected, verified, refused
	Problem      string
	Username     string // whose identity the bank asserted, when verified
	trace        *trace
	wire         *wireArtifacts
	swapIDToken  string
	session      client.SessionHandle
	tokens       client.TokenSet
	Claims       []claimRow
	ACR          string
	AuthTime     string
	Attempts     []attempt
}

// claimRow is one verified claim as the relying party's page shows it.
type claimRow struct{ Label, Value, Source string }

type attempt struct {
	Title, Result string
	Refused       bool
}

func (w *World) newRelyingParty(setup rpSetup) (*relyingParty, error) {
	decryption := map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{}
	if setup.encrypt {
		// One key per algorithm: the bank picks the key to encrypt to by
		// algorithm, from the JWK Set this relying party publishes.
		decryption[keys.IDTokenDecryption] = fapi.RSAOAEP256
		decryption[keys.UserInfoDecryption] = fapi.ECDHESA256KW
	}
	signing := map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.ES256, keys.DPoPProofSigning: fapi.ES256}
	km, err := ephemeral.NewKeyManagerWithDecryption(signing, decryption)
	if err != nil {
		return nil, err
	}
	thiefKeys, err := ephemeral.NewKeyManagerWithDecryption(signing, decryption)
	if err != nil {
		return nil, err
	}
	// The JWK Set this relying party registers with the bank: its
	// client-assertion key, and the keys to encrypt to it.
	var encryption []keys.EncryptionKeyUse
	for purpose, alg := range decryption {
		encryption = append(encryption, keys.EncryptionKeyUse{Decrypter: km, Purpose: purpose, Algorithm: alg})
	}
	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256}}, encryption)
	if err != nil {
		return nil, err
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	rp := &relyingParty{w: w, setup: setup, keys: km, jwks: jwks, sessions: memstore.NewSessionStore(), checks: map[string]*check{}}
	rp.client = &lazyClient{rp: rp, keys: km}
	rp.thief = &lazyClient{rp: rp, keys: thiefKeys}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", rp.home)
	mux.HandleFunc("GET /check", rp.show)
	mux.HandleFunc("GET "+callbackPath, rp.callback)
	protect := http.NewCrossOriginProtection()
	mux.Handle("POST /start", protect.Handler(http.HandlerFunc(rp.start)))
	mux.Handle("POST /attack", protect.Handler(http.HandlerFunc(rp.attack)))
	w.router[setup.host] = mux
	return rp, nil
}

// lazyClient is a FAPIgo client built from Alder Bank's published
// metadata the first time it's needed (the bank isn't listening yet when
// the demo starts).
type lazyClient struct {
	rp   *relyingParty
	keys *ephemeral.KeyManager

	mu sync.Mutex
	c  *client.Client
}

func (l *lazyClient) get(ctx context.Context) (*client.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c != nil {
		return l.c, nil
	}
	w, setup := l.rp.w, l.rp.setup
	fetcher, err := w.fetcher(setup.host)
	if err != nil {
		return nil, err
	}
	issuer, err := fapi.ParseIssuerURL(w.URL(bankHost, ""))
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
	algorithms := client.Algorithms{ClientAuthentication: fapi.ES256, DPoP: fapi.ES256, IDToken: fapi.ES256, UserInfo: fapi.ES256}
	deps := client.Dependencies{
		Sessions: l.rp.sessions, Keys: l.keys, IssuerKeys: issuerKeys,
		HTTP:  tracingClient{next: w.net.Client(setup.host)},
		Clock: client.SystemClock{}, Random: rand.Reader,
	}
	if setup.encrypt {
		// What the bank encrypts to this relying party, it decrypts with
		// its own key; the ID token and UserInfo response inside are still
		// verified as signed by the bank.
		algorithms.IDTokenKeyManagement, algorithms.IDTokenContentEncryption = fapi.RSAOAEP256, fapi.A256GCM
		algorithms.UserInfoKeyManagement, algorithms.UserInfoContentEncryption = fapi.ECDHESA256KW, fapi.A256GCM
		deps.Decryption = l.keys
	}
	limits := client.RecommendedLimits()
	limits.MaxIDTokenLifetime = 10 * time.Minute // Alder Bank's (server.RecommendedLimits)
	c, err := client.NewFromDiscovery(discovered, client.Config{
		ClientID: setup.clientID, RedirectURI: w.URL(setup.host, callbackPath),
		Profile: client.ProfileFAPISecurity, Assurance: client.AssuranceDevelopment,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		Algorithms:                     algorithms, Limits: limits,
		SenderConstrain:  storage.SenderConstrainDPoP,
		ClientAuthMethod: storage.ClientAuthMethodPrivateKeyJWT,
	}, deps)
	if err != nil {
		return nil, err
	}
	l.c = c
	return c, nil
}

func (rp *relyingParty) lookup(id string) (*check, bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	c, ok := rp.checks[id]
	return c, ok
}

func checkURL(id string) string { return "/check?id=" + id }

func (rp *relyingParty) home(w http.ResponseWriter, _ *http.Request) {
	rp.w.render(w, "rp-home", rpHomePage{Page: rp.w.page(rp.setup.name, rp.setup.host), Purpose: rp.setup.purpose, Requests: rp.describeRequest()})
}

// describeRequest is what this relying party asks the bank for, for its
// own page.
func (rp *relyingParty) describeRequest() []string {
	var out []string
	label := func(names []string) string {
		labels := make([]string, len(names))
		for i, n := range names {
			labels[i] = strings.ToLower(claimLabels[n])
		}
		return strings.Join(labels, ", ")
	}
	out = append(out, "In the ID token: "+label(rp.setup.idTokenClaims))
	out = append(out, "From UserInfo: "+label(rp.setup.userInfoClaims))
	if rp.setup.acr != "" {
		out = append(out, "A sign-in approved in the Alder Bank app (acr_values="+rp.setup.acr+")")
	}
	if rp.setup.hasMaxAge {
		out = append(out, "Within the last "+rp.setup.maxAge.String()+" (max_age)")
	}
	if rp.setup.encrypt {
		out = append(out, "Encrypted to "+rp.setup.name+", so only it can read them")
	}
	return out
}

// start begins an identity check: the FAPIgo client pushes the request,
// with its claims, acr_values and max_age, to the bank (PAR), and the
// browser goes to the bank with only the request_uri. A scenario other
// than "normal" is the attack lab's: the bank's ID token is replaced in
// flight with one from another sign-in.
func (rp *relyingParty) start(w http.ResponseWriter, r *http.Request) {
	ck := &check{ID: randomCode(8), Scenario: r.FormValue("scenario"), Status: "redirected", trace: &trace{}, wire: &wireArtifacts{}}
	switch ck.Scenario {
	case swapAlex, swapBrightline:
		// Captured earlier by the attack lab itself, never taken from
		// the browser.
		ck.swapIDToken = rp.w.captured.idTokenFor(ck.Scenario)
	default:
		ck.Scenario = "normal"
	}
	rp.mu.Lock()
	rp.checks[ck.ID] = ck
	rp.mu.Unlock()
	c, err := rp.client.get(r.Context())
	if err == nil {
		var session client.AuthorizationSession
		session, err = c.BeginAuthorization(withTrace(r.Context(), traceOptions{trace: ck.trace}), client.BeginAuthorizationRequest{
			Scope:     []string{"openid"},
			Claims:    client.RequestedClaims{IDToken: rp.setup.idTokenClaims, UserInfo: rp.setup.userInfoClaims},
			ACRValues: acrValues(rp.setup.acr), MaxAge: rp.setup.maxAge, HasMaxAge: rp.setup.hasMaxAge,
		})
		if err == nil {
			ck.session = session.Handle()
			for name, value := range map[string]string{sessionCookie: session.Handle().String(), checkCookie: ck.ID} {
				http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			}
			u := session.URL()
			// Not an open redirect: Alder Bank's authorization endpoint,
			// from its discovery metadata.
			http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: see above
			return
		}
	}
	rp.finish(ck, "refused", describeError(err))
	http.Redirect(w, r, checkURL(ck.ID), http.StatusSeeOther)
}

func acrValues(acr string) []string {
	if acr == "" {
		return nil
	}
	return []string{acr}
}

func (rp *relyingParty) finish(ck *check, status, problem string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	ck.Status, ck.Problem = status, problem
}

// callback receives the bank's authorization response, redeems the code
// for an ID token, checks how the customer signed in, and fetches the
// approved UserInfo claims.
func (rp *relyingParty) callback(w http.ResponseWriter, r *http.Request) {
	sessionC, err1 := r.Cookie(sessionCookie)
	checkC, err2 := r.Cookie(checkCookie)
	clearCookies(w, sessionCookie, checkCookie)
	var ck *check
	ok := false
	if err2 == nil {
		ck, ok = rp.lookup(checkC.Value)
	}
	if err1 != nil || !ok {
		rp.w.renderError(w, rp.setup.host, http.StatusBadRequest, "No identity check in progress", "This browser didn't start one here.")
		return
	}
	handle, err := client.ParseSessionHandle(sessionC.Value)
	if err != nil {
		rp.w.renderError(w, rp.setup.host, http.StatusBadRequest, "No identity check in progress", notStartedHere)
		return
	}
	rp.complete(r.Context(), ck, handle, r.URL.RawQuery)
	http.Redirect(w, r, checkURL(ck.ID), http.StatusSeeOther)
}

func (rp *relyingParty) complete(ctx context.Context, ck *check, handle client.SessionHandle, rawQuery string) {
	ctx = withTrace(ctx, traceOptions{trace: ck.trace, captured: ck.wire, swapIDToken: ck.swapIDToken})
	c, err := rp.client.get(ctx)
	if err != nil {
		rp.finish(ck, "refused", err.Error())
		return
	}
	result, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: handle})
	if err != nil {
		rp.finish(ck, "refused", describeError(err))
		return
	}
	if denied, ok := result.(client.CallbackDenied); ok {
		rp.finish(ck, "refused", "Alder Bank answered "+denied.Code+": "+denied.Description)
		return
	}
	tokens, err := c.ExchangeCode(ctx, result.(client.CallbackSuccess).Response)
	if err != nil {
		rp.finish(ck, "refused", describeError(err))
		return
	}
	idClaims := tokens.IDTokenClaims
	// OIDC Core §3.1.3.7: the relying party decides whether the
	// authentication it got is the one it asked for. acr_values is a
	// request the bank may not meet, so the relying party checks the acr
	// it was given. max_age is checked twice without code here: the bank
	// enforces it, and ExchangeCode refused an ID token whose auth_time
	// is missing or older.
	if rp.setup.acr != "" && idClaims.ACR != rp.setup.acr {
		rp.finish(ck, "refused", fmt.Sprintf("%s needs a sign-in approved in the Alder Bank app (acr %s), and the ID token says acr %s", rp.setup.name, rp.setup.acr, idClaims.ACR))
		return
	}
	info, err := c.FetchUserInfo(ctx, tokens)
	if err != nil {
		rp.finish(ck, "refused", "UserInfo: "+describeError(err))
		return
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	ck.tokens, ck.Username, ck.Status = tokens, tokens.Subject, "verified"
	ck.ACR, ck.AuthTime = idClaims.ACR, idClaims.AuthTime.Format("15:04:05")
	ck.Claims = claimRows(idClaims.Parameters, "ID token")
	ck.Claims = append(ck.Claims, claimRows(info.Parameters, "UserInfo")...)
}

// claimRows are the identity claims among params, from source.
func claimRows(params map[string]json.RawMessage, source string) []claimRow {
	var rows []claimRow
	for _, name := range identityClaims {
		raw, ok := params[name]
		if !ok {
			continue
		}
		rows = append(rows, claimRow{Label: claimLabels[name], Value: claimText(raw), Source: source})
	}
	return rows
}

// claimText is a claim's value for a page: a string as itself, an
// address on one line.
func claimText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var address map[string]string
	if json.Unmarshal(raw, &address) == nil {
		return strings.Join([]string{address["street_address"], address["locality"], address["postal_code"]}, ", ")
	}
	return string(raw)
}

func (rp *relyingParty) show(w http.ResponseWriter, r *http.Request) {
	ck, ok := rp.lookup(r.URL.Query().Get("id"))
	if !ok {
		rp.w.renderError(w, rp.setup.host, http.StatusNotFound, "Unknown identity check", "Start a new one.")
		return
	}
	rp.mu.Lock()
	view := *ck
	view.Attempts = append([]attempt(nil), ck.Attempts...)
	rp.mu.Unlock()
	rp.w.render(w, "rp-check", rpCheckPage{
		Page: rp.w.page(rp.setup.name, rp.setup.host), Check: &view, Trace: ck.trace.Steps(),
		AttackLab: rp.setup.encrypt,
	})
}

// userInfoNames is the claim names a UserInfo response carried.
func userInfoNames(info client.UserInfo) []string {
	var names []string
	for name := range info.Parameters {
		if slices.Contains(identityClaims, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
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

// clearCookies expires the callback's cookies. The session they carry is
// single-use — consumed by this callback whatever its outcome — so
// nothing should keep presenting it.
func clearCookies(w http.ResponseWriter, names ...string) {
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}
