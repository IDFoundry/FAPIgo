package linked

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"github.com/idfoundry/fapigo/server/interactioncookie"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const (
	bankKeyID         = "alder-1"
	authorizePath     = "/authorize"
	connectedAppsPath = "/connected-apps"
	approvalFailed    = "Approval failed"
)

// bank is Alder Bank's authorization server, with its own sign-in and
// consent page and its Connected apps page.
type bank struct {
	w   *World
	srv *server.Server
	// cfg and deps are what srv was built with, for the API's verifier.
	cfg  server.Config
	deps server.Dependencies
	// interaction carries the consent page's state in an encrypted
	// cookie: every instance would share its key.
	interaction *interactioncookie.Cookie

	mu sync.Mutex
	// connections is the bank's own record of each grant a customer
	// approved, by grant ID: what its Connected apps page lists.
	connections map[string]*connection
}

// connection is one app a customer connected to their accounts.
type connection struct {
	GrantID, Customer, App string
	Accounts               []string
	ApprovedAt             time.Time
	RevokedAt              time.Time
}

func (w *World) newBank(apps apps) (*bank, error) {
	issuer, err := fapi.ParseIssuerURL(w.URL(bankHost, ""))
	if err != nil {
		return nil, err
	}
	var endpoints server.Endpoints
	for _, e := range []struct {
		dst  *fapi.URL
		path string
	}{
		{&endpoints.Authorization, authorizePath}, {&endpoints.PushedAuthorizationRequest, "/par"},
		{&endpoints.Token, "/token"}, {&endpoints.JWKS, "/jwks"},
	} {
		if *e.dst, err = fapi.ParseEndpointURL(w.URL(bankHost, e.path)); err != nil {
			return nil, err
		}
	}
	signer, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return nil, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.IDTokenSigning: signer, keys.AccessTokenSigning: signer},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.IDTokenSigning: fapi.ES256, keys.AccessTokenSigning: fapi.ES256},
		map[keys.SigningPurpose]string{keys.IDTokenSigning: bankKeyID, keys.AccessTokenSigning: bankKeyID},
	)
	if err != nil {
		return nil, err
	}
	accessTokens, err := server.NewJWTAccessTokens(manager, fapi.ES256)
	if err != nil {
		return nil, err
	}
	registry, err := newRARRegistry()
	if err != nil {
		return nil, err
	}
	var registered []storage.RegisteredClient
	var specs []ephemeral.ClientKeySpec
	for _, a := range []app{apps.pocketwise, apps.thriftly} {
		client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                       a.clientID,
			RedirectURIs:             []fapi.RegisteredRedirectURI{a.redirectURI(w)},
			ClientAuthMethod:         storage.ClientAuthMethodPrivateKeyJWT,
			ClientAssertionAlgorithm: fapi.ES256,
			SenderConstrain:          storage.SenderConstrainDPoP,
			AllowedScopes:            []string{"openid", "accounts", "offline_access"},
			// RFC 9396 §10: the apps may ask for account access only.
			AuthorizationDetailsTypes: []string{accountAccessType.Type},
			Display:                   storage.ClientDisplay{Name: a.name},
		})
		if err != nil {
			return nil, err
		}
		registered = append(registered, client)
		specs = append(specs, ephemeral.ClientKeySpec{ClientID: a.clientID, JWKS: a.authJWKS})
	}
	clientKeys, err := ephemeral.NewClientKeySource(nil, specs)
	if err != nil {
		return nil, err
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return nil, err
	}
	interaction, err := interactioncookie.New([][]byte{cookieKey}, interactioncookie.Options{})
	if err != nil {
		return nil, err
	}

	limits := server.RecommendedLimits()
	// The customer approves once for 90 days: the refresh token lasts
	// that long, and isn't rotated (FAPI 2.0), so the consent ends when it
	// does.
	limits.RefreshTokenLifetime = consentLifetime

	b := &bank{w: w, interaction: interaction, connections: map[string]*connection{}}
	b.cfg = server.Config{
		Issuer: issuer, Endpoints: endpoints, Profile: server.ProfileFAPISecurity,
		Algorithms: server.RecommendedAlgorithms(), Limits: limits,
		Assurance: server.AssuranceDevelopment, RAR: registry,
	}
	b.deps = server.Dependencies{
		Clients:      memstore.NewClientRepository(registered),
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       memstore.NewReplayStore(),
		ClientKeys:   clientKeys,
		Keys:         manager,
		AccessTokens: accessTokens,
		// The revocation store the bank and its API share: RevokeGrant
		// writes to it, and both read it.
		Revocation:             memstore.NewRevocationStore(),
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  w.clock,
		Random:                 rand.Reader,
		// Each client's types are its registration's; no further rule.
		AuthorizationCodeRARPolicy: server.AllowRequestedAuthorizationDetails{},
	}
	if b.srv, err = server.New(b.cfg, b.deps); err != nil {
		return nil, err
	}
	// A registration naming a detail type the bank doesn't register (a
	// typo, say) fails here, not at the first request for it.
	for _, c := range registered {
		if err := b.srv.CheckClientRegistration(c); err != nil {
			return nil, err
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", b.discovery)
	mux.HandleFunc("GET /jwks", b.jwks)
	mux.HandleFunc("POST /par", b.par)
	mux.HandleFunc("GET "+authorizePath, b.authorize)
	protect := http.NewCrossOriginProtection()
	// The interaction cookie is SameSite, but a sibling *.localhost host
	// is the same site; refusing cross-origin POSTs is the CSRF defence
	// server.InteractionHandle's doc comment asks for.
	mux.Handle("POST "+authorizePath, protect.Handler(http.HandlerFunc(b.decide)))
	mux.HandleFunc("POST /token", b.token)
	mux.HandleFunc("GET "+connectedAppsPath, b.connectedApps)
	mux.Handle("POST "+connectedAppsPath, protect.Handler(http.HandlerFunc(b.revoke)))
	w.router[bankHost] = mux
	return b, nil
}

// redirectURI is where the app's authorization responses go: Pocketwise's
// callback, or Thriftly's own site, which isn't part of the demo.
func (a app) redirectURI(w *World) fapi.RegisteredRedirectURI {
	if a.clientID == pocketwiseClientID {
		return fapi.RegisteredRedirectURI(w.URL(pocketwiseHost, callbackPath))
	}
	return "https://thriftly.example/callback"
}

func (b *bank) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.srv.Metadata(r.Context()))
}

func (b *bank) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := b.srv.PublicJWKS(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	set.WriteJSON(w)
}

func (b *bank) par(w http.ResponseWriter, r *http.Request) {
	req, err := server.PushAuthorizationRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result, err := b.srv.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// token redeems an authorization code, or a refresh token.
func (b *bank) token(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	var result server.TokenResult
	switch req.GrantType() {
	case "authorization_code":
		result, err = b.srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
	case "refresh_token":
		result, err = b.srv.RefreshAccessToken(r.Context(), req.RefreshToken())
	default:
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "authorization_code or refresh_token").WriteJSON(w)
		return
	}
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// authorize starts the interaction and shows the sign-in and consent
// page. The interaction goes with the browser in a cookie the bank
// encrypts, so any instance of the bank can finish it, and the page's
// form carries the tag that ties it to this interaction.
func (b *bank) authorize(w http.ResponseWriter, r *http.Request) {
	// Local, never a redirect: an unreadable request names no
	// redirect URI it can be trusted with.
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Sign-in could not start", publicMessage(err, "The sign-in request is malformed."))
		return
	}
	action, err := b.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusInternalServerError, "Sign-in could not start", publicMessage(err, "Something went wrong. Please try again."))
		return
	}
	switch a := action.(type) {
	case server.InteractionRequired:
		tag, err := b.interaction.Set(w, a, b.w.clock.Now())
		if err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, "Sign-in could not start", publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		b.w.render(w, "consent", b.consentPage(a.Interaction, tag, ""))
	case server.RedirectResponse:
		http.Redirect(w, r, a.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		b.w.renderError(w, bankHost, a.Error.HTTPStatus(), "Alder Bank refused the request", string(a.Error.Code())+": "+a.Error.PublicDescription())
	}
}

// consentPage lists the signed-in customer's accounts to choose from.
// The demo has one customer, so it shows Sam's.
func (b *bank) consentPage(in server.InteractionRequest, tag, problem string) consentPage {
	page := consentPage{Interaction: tag, Page: b.w.page("Alder Bank", bankHost), ClientName: in.ClientDisplay.Name, Problem: problem}
	if page.ClientName == "" {
		page.ClientName = string(in.ClientID)
	}
	access, _ := accessOf(in.AuthorizationDetails)
	page.Actions = strings.ReplaceAll(strings.Join(access.Actions, ", "), "_", " ")
	page.Until = b.w.clock.Now().Add(consentLifetime).Format("2 January 2006")
	sam, _ := customerByName("sam")
	for _, a := range sam.accounts {
		if len(access.Accounts) == 0 || slices.Contains(access.Accounts, a.IBAN) {
			page.Accounts = append(page.Accounts, a)
		}
	}
	return page
}

// decide signs the customer in and records which accounts they chose
// to share, under a grant ID the bank keeps on its Connected apps page.
func (b *bank) decide(w http.ResponseWriter, r *http.Request) {
	tag := r.PostFormValue(interactioncookie.FormField)
	handle, in, err := b.interaction.Read(r, b.w.clock.Now(), tag)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Session expired", "This browser has no sign-in in progress.")
		return
	}
	if err := r.ParseForm(); err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Malformed form", formUnreadable)
		return
	}
	result := server.Deny("the customer declined")
	if r.PostForm.Get("decision") == "approve" {
		c, ok := customerByName(r.PostForm.Get("username"))
		if !ok || !hmac.Equal([]byte(c.pin), []byte(r.PostForm.Get("pin"))) {
			b.w.render(w, "consent", b.consentPage(in, tag, "That username and PIN don't match."))
			return
		}
		var chosen []string
		for _, iban := range r.PostForm["account"] {
			if _, mine := c.account(iban); mine && !slices.Contains(chosen, iban) {
				chosen = append(chosen, iban)
			}
		}
		if len(chosen) == 0 {
			b.w.render(w, "consent", b.consentPage(in, tag, "Choose at least one account to share."))
			return
		}
		if result, err = b.approve(c, in, chosen); err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, "Something went wrong. Please try again."))
			return
		}
	}
	b.interaction.Clear(w)
	outcome, err := b.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, "Something went wrong. Please try again."))
		return
	}
	switch o := outcome.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, o.Destination().String(), http.StatusFound)
	case server.AuthorizationLocalError:
		b.w.renderError(w, bankHost, o.Error.HTTPStatus(), approvalFailed, string(o.Error.Code())+": "+o.Error.PublicDescription())
	}
}

// approve grants c's chosen accounts to the app, naming the grant so
// the bank can revoke it from Connected apps.
func (b *bank) approve(c customer, in server.InteractionRequest, chosen []string) (server.InteractionResult, error) {
	access, _ := accessOf(in.AuthorizationDetails)
	detail, err := extension.RARSet(accountAccessType, accountAccess{Accounts: chosen, Actions: access.Actions})
	if err != nil {
		return nil, err
	}
	subjectID, err := server.NewSubjectID(c.username)
	if err != nil {
		return nil, err
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		return nil, err
	}
	auth, err := server.NewAuthenticationContext(b.w.clock.Now(), "urn:alder-bank:acr:pin", []string{"pin"})
	if err != nil {
		return nil, err
	}
	grantID := randomCode(16)
	name := in.ClientDisplay.Name
	b.mu.Lock()
	b.connections[grantID] = &connection{GrantID: grantID, Customer: c.username, App: name, Accounts: chosen, ApprovedAt: b.w.clock.Now()}
	b.mu.Unlock()
	return server.Authorize(subject, auth, server.GrantedAuthorization{
		Scope: in.Scope, AuthorizationDetails: []json.RawMessage{detail}, GrantID: grantID,
	}), nil
}

// connectedApps is the customer's list of apps with access to their
// accounts.
func (b *bank) connectedApps(w http.ResponseWriter, _ *http.Request) {
	page := connectedAppsPage{Page: b.w.page("Alder Bank: Connected apps", bankHost)}
	b.mu.Lock()
	for _, c := range b.connections {
		view := connectionView{GrantID: c.GrantID, App: c.App, ApprovedAt: c.ApprovedAt.Format("2 Jan 2006 15:04"),
			Until: c.ApprovedAt.Add(consentLifetime).Format("2 Jan 2006"), Revoked: !c.RevokedAt.IsZero()}
		for _, iban := range c.Accounts {
			sam, _ := customerByName(c.Customer)
			a, _ := sam.account(iban)
			view.Accounts = append(view.Accounts, a.Name+" ····"+iban[len(iban)-4:])
		}
		view.Expired = !view.Revoked && b.w.clock.Now().After(c.ApprovedAt.Add(consentLifetime))
		page.Connections = append(page.Connections, view)
	}
	b.mu.Unlock()
	slices.SortFunc(page.Connections, func(x, y connectionView) int { return strings.Compare(y.ApprovedAt, x.ApprovedAt) })
	b.w.render(w, "connected-apps", page)
}

// revoke withdraws a connected app's access: server.RevokeGrant stops
// its refresh token and every access token issued from the grant.
func (b *bank) revoke(w http.ResponseWriter, r *http.Request) {
	grantID := r.FormValue("grant_id")
	b.mu.Lock()
	c, ok := b.connections[grantID]
	b.mu.Unlock()
	if !ok {
		b.w.renderError(w, bankHost, http.StatusNotFound, "No such connection", "This app isn't connected.")
		return
	}
	if err := b.srv.RevokeGrant(r.Context(), grantID); err != nil {
		b.w.renderError(w, bankHost, http.StatusInternalServerError, "Revoking failed", publicMessage(err, "Something went wrong. Please try again."))
		return
	}
	b.mu.Lock()
	c.RevokedAt = b.w.clock.Now()
	b.mu.Unlock()
	http.Redirect(w, r, connectedAppsPath, http.StatusSeeOther)
}
