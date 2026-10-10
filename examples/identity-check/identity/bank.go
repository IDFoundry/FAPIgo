package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/idfoundry/fapigo/server/interactioncookie"
	"net/http"
	"net/url"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const (
	bankKeyID      = "alder-1"
	authorizePath  = "/authorize"
	userinfoPath   = "/userinfo"
	approvalFailed = "Approval failed"
)

// The Authentication Context Class References Alder Bank reports.
const (
	// acrApp is a PIN and an approval in Alder Bank's phone app.
	acrApp = "urn:alder-bank:acr:app"
	// acrPIN is a PIN alone.
	acrPIN = "urn:alder-bank:acr:pin"
)

// rememberedSignIn is how long ago the demo's "earlier sign-in" happened.
const rememberedSignIn = 3 * time.Hour

// bank is Alder Bank's OpenID Provider: its authorization server, its
// own sign-in and consent page, and its UserInfo endpoint.
type bank struct {
	w        *World
	srv      *server.Server
	clients  storage.ClientRepository
	verifier *resource.Verifier
	// interaction carries the consent page's state in an encrypted
	// cookie: every instance would share its key.
	interaction *interactioncookie.Cookie
}

func (w *World) newBank(rps ...*relyingParty) (*bank, error) {
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
	purposes := []keys.SigningPurpose{keys.IDTokenSigning, keys.AccessTokenSigning, keys.UserInfoSigning}
	specs := make([]keys.SignerSpec, 0, len(purposes))
	for _, p := range purposes {
		specs = append(specs, keys.SignerSpec{Purpose: p, Algorithm: fapi.ES256, Signer: signer, KeyID: bankKeyID})
	}
	manager, err := keys.NewKeyManagerFromSigners(specs)
	if err != nil {
		return nil, err
	}
	accessTokens, err := server.NewJWTAccessTokens(manager, fapi.ES256)
	if err != nil {
		return nil, err
	}

	var registered []storage.RegisteredClient
	var keySpecs []ephemeral.ClientKeySpec
	for _, rp := range rps {
		cfg := storage.RegisteredClientConfig{
			ID:                       rp.setup.clientID,
			RedirectURIs:             []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(w.URL(rp.setup.host, callbackPath))},
			ClientAuthMethod:         storage.ClientAuthMethodPrivateKeyJWT,
			ClientAssertionAlgorithm: fapi.ES256,
			SenderConstrain:          storage.SenderConstrainDPoP,
			AllowedScopes:            []string{"openid"},
			Display:                  storage.ClientDisplay{Name: rp.setup.name},
		}
		if rp.setup.encrypt {
			// The client's registration asks for its ID tokens and UserInfo
			// responses encrypted to it (OIDC Dynamic Client Registration
			// §2's id_token_encrypted_response_alg/enc and userinfo_…).
			cfg.IDTokenEncryptionKeyManagement, cfg.IDTokenEncryptionContentEncryption = fapi.RSAOAEP256, fapi.A256GCM
			cfg.UserInfoEncryptionKeyManagement, cfg.UserInfoEncryptionContentEncryption = fapi.ECDHESA256KW, fapi.A256GCM
		}
		client, err := storage.NewRegisteredClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("register %s: %w", rp.setup.name, err)
		}
		registered = append(registered, client)
		keySpecs = append(keySpecs, ephemeral.ClientKeySpec{ClientID: rp.setup.clientID, JWKS: rp.jwks})
	}
	clientKeys, err := ephemeral.NewClientKeySource(nil, keySpecs)
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

	algs := server.RecommendedAlgorithms()
	algs.UserInfo = fapi.ES256
	algs.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	algs.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	algs.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.ECDHESA256KW}
	algs.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}

	b := &bank{w: w, clients: memstore.NewClientRepository(registered), interaction: interaction}
	cfg := server.Config{
		Issuer: issuer, Endpoints: endpoints, Profile: server.ProfileFAPISecurity,
		Algorithms: algs, Limits: server.RecommendedLimits(), Assurance: server.AssuranceDevelopment,
	}
	deps := server.Dependencies{
		Clients:      b.clients,
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       memstore.NewReplayStore(),
		// Each client's registered JWK Set: the keys that verify its
		// client assertions, and the keys to encrypt its ID tokens and
		// UserInfo responses to.
		ClientKeys:             clientKeys,
		ClientEncryptionKeys:   clientKeys,
		Keys:                   manager,
		AccessTokens:           accessTokens,
		Revocation:             memstore.NewRevocationStore(),
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  server.SystemClock{},
		Random:                 rand.Reader,
		// The bank's own records of who its customers are. It releases a
		// claim only when the customer approved it on the consent page.
		IdentityClaims: customerClaims{},
	}
	if b.srv, err = server.New(cfg, deps); err != nil {
		return nil, err
	}
	// The UserInfo endpoint runs in the bank's own process, so its
	// verifier comes straight from the server configuration.
	if b.verifier, err = serverresource.NewVerifier(cfg, deps, serverresource.Options{}); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", b.discovery)
	mux.HandleFunc("GET /jwks", b.jwks)
	mux.HandleFunc("POST /par", b.par)
	mux.HandleFunc("GET "+authorizePath, b.authorize)
	// The interaction cookie is SameSite, but a sibling *.localhost host
	// is the same site; refusing cross-origin POSTs is the CSRF defence
	// server.InteractionHandle's doc comment asks for.
	mux.Handle("POST "+authorizePath, http.NewCrossOriginProtection().Handler(http.HandlerFunc(b.decide)))
	mux.HandleFunc("POST /token", b.token)
	mux.HandleFunc("GET "+userinfoPath, b.userinfo)
	w.router[bankHost] = mux
	return b, nil
}

// customerClaims is Alder Bank's IdentityClaimsSource: its customers'
// verified identity.
type customerClaims struct{}

// ResolveIdentityClaims implements server.IdentityClaimsSource. names
// holds only claims the client asked for and the customer approved.
func (customerClaims) ResolveIdentityClaims(_ context.Context, subject string, names []string) (map[string]json.RawMessage, error) {
	c, ok := customerByName(subject)
	if !ok {
		return nil, fmt.Errorf("no customer %q", subject)
	}
	out := map[string]json.RawMessage{}
	for _, name := range names {
		if raw, ok := c.claimValue(name); ok {
			out[name] = raw
		}
	}
	return out, nil
}

// discoveryDocument is server.Metadata plus what a deployment adds
// itself: its UserInfo endpoint, which this package doesn't implement,
// and the identity claims it can release.
type discoveryDocument struct {
	server.Metadata
	UserinfoEndpoint string   `json:"userinfo_endpoint"`
	ClaimsSupported  []string `json:"claims_supported"`
	ACRValues        []string `json:"acr_values_supported"`
}

func (b *bank) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(discoveryDocument{
		Metadata:         b.srv.Metadata(r.Context()),
		UserinfoEndpoint: b.w.URL(bankHost, userinfoPath),
		ClaimsSupported:  append([]string{"sub", "iss", "auth_time", "acr"}, identityClaims...),
		ACRValues:        []string{acrApp, acrPIN},
	})
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

func (b *bank) token(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	if req.GrantType() != "authorization_code" {
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "only authorization_code is supported").WriteJSON(w)
		return
	}
	result, err := b.srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// userinfo is Alder Bank's UserInfo endpoint (OIDC Core §5.3): the
// claims the customer approved for UserInfo, signed by the bank and, for
// a client that registered for it, encrypted to the client.
func (b *bank) userinfo(w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse(b.w.URL(bankHost, userinfoPath))
	if err != nil {
		internalError(w, err)
		return
	}
	authz, err := b.verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r, target))
	if err != nil {
		resource.WriteError(w, err)
		return
	}
	// Only the claims the client requested and the customer approved,
	// which the access token carries: a UserInfo call has no other link
	// back to the authorization.
	body, err := serverresource.UserInfoClaims(r.Context(), authz, customerClaims{})
	if err != nil {
		var rerr *resource.Error
		if errors.As(err, &rerr) {
			resource.WriteError(w, rerr)
			return
		}
		resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized, "unknown customer").WriteJSON(w)
		return
	}
	// Signed for the token's own client and subject: a token for a client
	// the bank no longer knows is a 401, the token's problem, not the
	// bank's.
	signed, err := serverresource.SignUserInfoResponse(r.Context(), b.srv, b.clients, authz, body)
	if err != nil {
		var rerr *resource.Error
		var srvErr *server.Error
		switch {
		case errors.As(err, &rerr):
			resource.WriteError(w, rerr)
		case errors.As(err, &srvErr):
			srvErr.WriteJSON(w)
		default:
			resource.NewError(resource.ErrorServerError, http.StatusInternalServerError, "failed to sign the UserInfo response").WriteJSON(w)
		}
		return
	}
	authz.SetDPoPNonce(w.Header())
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = w.Write([]byte(signed)) // #nosec G705 -- a signed compact JWT (application/jwt), never rendered as HTML
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
		b.w.renderError(w, bankHost, http.StatusBadRequest, signInFailedToStart, publicMessage(err, "The sign-in request is malformed."))
		return
	}
	action, err := b.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusInternalServerError, signInFailedToStart, publicMessage(err, tryAgain))
		return
	}
	switch a := action.(type) {
	case server.InteractionRequired:
		tag, err := b.interaction.Set(w, a, time.Now())
		if err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, signInFailedToStart, publicMessage(err, tryAgain))
			return
		}
		b.w.render(w, "consent", b.consentPage(a.Interaction, tag, ""))
	case server.RedirectResponse:
		http.Redirect(w, r, a.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		b.w.renderError(w, bankHost, a.Error.HTTPStatus(), "Alder Bank refused the request", string(a.Error.Code())+": "+a.Error.PublicDescription())
	}
}

// claimView is one requested claim on the consent page.
type claimView struct {
	Name, Label, Where string
}

// identityClaims are the claims Alder Bank can release, in the order its
// consent page lists them.
var identityClaims = []string{"given_name", "family_name", "birthdate", "email", "phone_number", "address"}

var claimLabels = map[string]string{
	"given_name": "First name", "family_name": "Last name", "birthdate": "Date of birth",
	"email": "Email address", "phone_number": "Phone number", "address": "Home address",
}

func (b *bank) consentPage(in server.InteractionRequest, tag, problem string) consentPage {
	page := consentPage{Interaction: tag, Page: b.w.page("Alder Bank", bankHost), ClientName: in.ClientDisplay.Name, Problem: problem}
	if page.ClientName == "" {
		page.ClientName = string(in.ClientID)
	}
	for _, name := range identityClaims {
		where := ""
		switch {
		case slices.Contains(in.RequestedClaims.IDToken, name):
			where = "ID token"
		case slices.Contains(in.RequestedClaims.UserInfo, name):
			where = "UserInfo"
		default:
			continue
		}
		page.Claims = append(page.Claims, claimView{Name: name, Label: claimLabels[name], Where: where})
	}
	page.StrongRequested = slices.Contains(in.ACRValues, acrApp)
	if in.HasMaxAge {
		page.MaxAge = in.MaxAge.String()
	}
	page.Remembered = time.Now().Add(-rememberedSignIn).Format("15:04")
	return page
}

// decide signs the customer in, the way they chose, and records which
// claims they approved for release.
func (b *bank) decide(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Malformed form", formUnreadable)
		return
	}
	tag := r.PostForm.Get(interactioncookie.FormField)
	handle, in, err := b.interaction.Read(r, time.Now(), tag)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Session expired", "This browser has no sign-in in progress.")
		return
	}
	result := server.Deny("the customer declined")
	if r.PostForm.Get("decision") == "approve" {
		c, ok := customerByName(r.PostForm.Get("username"))
		method := r.PostForm.Get("method")
		if !ok || (method != "remembered" && !hmac.Equal([]byte(c.pin), []byte(r.PostForm.Get("pin")))) {
			b.w.render(w, "consent", b.consentPage(in, tag, "That username and PIN don't match."))
			return
		}
		if result, err = authorizeAs(c, method, in, r.PostForm["claim"], time.Now()); err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, tryAgain))
			return
		}
	}
	b.interaction.Clear(w)
	outcome, err := b.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, tryAgain))
		return
	}
	switch o := outcome.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, o.Destination().String(), http.StatusSeeOther) // after a form POST: never 307
	case server.AuthorizationLocalError:
		b.w.renderError(w, bankHost, o.Error.HTTPStatus(), approvalFailed, string(o.Error.Code())+": "+o.Error.PublicDescription())
	}
}

// authorizeAs is c signing in by method at now, approving the claims
// named in approved: the app (a PIN and an approval on their phone), a
// PIN alone, or an earlier app sign-in the bank remembered.
func authorizeAs(c customer, method string, in server.InteractionRequest, approved []string, now time.Time) (server.InteractionResult, error) {
	acr, amr, authTime := acrApp, []string{"pin", "hwk"}, now
	switch method {
	case "pin":
		acr, amr = acrPIN, []string{"pin"}
	case "remembered":
		authTime = now.Add(-rememberedSignIn)
	}
	subjectID, err := server.NewSubjectID(c.username)
	if err != nil {
		return nil, err
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		return nil, err
	}
	auth, err := server.NewAuthenticationContext(authTime, acr, amr)
	if err != nil {
		return nil, err
	}
	// Only claims that were requested can be approved: the server
	// refuses anything else.
	requested := in.RequestedClaims.Names()
	var release []string
	for _, name := range approved {
		if slices.Contains(requested, name) {
			release = append(release, name)
		}
	}
	return server.Authorize(subject, auth, server.GrantedAuthorization{Scope: in.Scope, ApprovedIdentityClaims: release}), nil
}
