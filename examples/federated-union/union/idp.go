package union

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/idfoundry/fapigo/server/interactioncookie"
	"log"
	"net/http"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// citizen is one person an identity provider can sign in.
type citizen struct {
	sub, given, family, birthdate, email, address string
}

// claims is c's identity claims, JSON-encoded, with nationality set to
// the issuing country.
func (c citizen) claims(nationality string) map[string]json.RawMessage {
	enc := func(v string) json.RawMessage { raw, _ := json.Marshal(v); return raw }
	return map[string]json.RawMessage{
		"given_name": enc(c.given), "family_name": enc(c.family), "birthdate": enc(c.birthdate),
		"email": enc(c.email), "address": json.RawMessage(fmt.Sprintf(`{"formatted":%s}`, enc(c.address))),
		"nationality": enc(nationality),
	}
}

// identityProvider is a country's national identity provider: a FAPI
// 2.0 authorization server that registers foreign services automatically
// through the Union's federation.
type identityProvider struct {
	entity   *entity
	country  country
	srv      *server.Server
	fedKey   signingKey
	forgedBy *federation.TrustMarkIssuer // EastID signing its own mark, for the forge scene
	w        *World

	// interaction carries the consent page's state in an encrypted
	// cookie: every instance would share its key.
	interaction *interactioncookie.Cookie
}

const (
	authorizePath = "/authorize"
	signInFailed  = "Sign-in failed"
)

func (w *World) newIdentityProvider(c country, ta *entity) (*identityProvider, error) {
	host := countryHost("id", c.key)
	id := w.entityID(host)
	issuer, err := fapi.ParseIssuerURL(id)
	if err != nil {
		return nil, err
	}
	endpoint := func(path string) (fapi.URL, error) { return fapi.ParseEndpointURL(id + path) }
	authz, err := endpoint(authorizePath)
	if err != nil {
		return nil, err
	}
	tokenURL, err := endpoint("/token")
	if err != nil {
		return nil, err
	}
	parURL, err := endpoint("/par")
	if err != nil {
		return nil, err
	}
	jwksURL, err := endpoint("/jwks")
	if err != nil {
		return nil, err
	}

	fedKey, err := newSigningKey(c.key+"-id-fed-1", keys.FederationEntitySigning)
	if err != nil {
		return nil, err
	}
	tokenSigner, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return nil, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{
			keys.FederationEntitySigning: fedKey.signer, keys.IDTokenSigning: tokenSigner, keys.AccessTokenSigning: tokenSigner,
		},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{
			keys.FederationEntitySigning: fapi.ES256, keys.IDTokenSigning: fapi.ES256, keys.AccessTokenSigning: fapi.ES256,
		},
		map[keys.SigningPurpose]string{
			keys.FederationEntitySigning: fedKey.kid, keys.IDTokenSigning: c.key + "-id-token-1", keys.AccessTokenSigning: c.key + "-id-token-1",
		},
	)
	if err != nil {
		return nil, err
	}
	accessTokens, err := server.NewJWTAccessTokens(manager, fapi.ES256)
	if err != nil {
		return nil, err
	}
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	if err != nil {
		return nil, err
	}
	fetcher, err := w.fetcher(host)
	if err != nil {
		return nil, err
	}

	cfg := server.Config{
		Issuer:     issuer,
		Endpoints:  server.Endpoints{Authorization: authz, Token: tokenURL, PushedAuthorizationRequest: parURL, JWKS: jwksURL},
		Profile:    server.ProfileFAPISecurity,
		Algorithms: server.RecommendedAlgorithms(),
		Limits:     server.RecommendedLimits(),
		Assurance:  server.AssuranceDevelopment,
		Federation: server.FederationConfig{
			EntityID: id, AuthorityHints: []string{ta.id}, Lifetime: statementLifetime, Algorithm: fapi.ES256,
		},
		// Services register themselves on first use: trusted through the
		// Union, or directly through this country's own authority.
		AutomaticRegistration: server.AutomaticRegistrationConfig{
			TrustAnchors:  []federation.TrustAnchor{anchor(w.union), anchor(ta)},
			AllowedScopes: []string{"openid"},
			MaxPathLength: 4, MaxAuthorityHints: 5,
			MaxStatementLifetime: statementLifetime + time.Hour, MaxClockSkew: 30 * time.Second,
			// Short, so suspending a country takes effect within the
			// demo rather than after a real deployment's caching period.
			MaxCacheAge: 10 * time.Second,
			// A refused service only sees invalid_client; the reason is
			// for the identity provider's operator.
			OnResolutionFailure: func(_ context.Context, clientID fapi.ClientID, err error) {
				log.Printf("%s refused automatic registration of %s: %v", c.idpName, clientID, err)
			},
		},
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return nil, err
	}
	interaction, err := interactioncookie.New([][]byte{cookieKey}, interactioncookie.Options{})
	if err != nil {
		return nil, err
	}
	idp := &identityProvider{country: c, fedKey: fedKey, w: w, interaction: interaction}
	deps := server.Dependencies{
		Clients:                memstore.NewClientRepository(nil),
		Transactions:           memstore.NewTransactionStore(),
		Grants:                 memstore.NewGrantStore(),
		Replay:                 memstore.NewReplayStore(),
		ClientKeys:             clientKeys,
		Keys:                   manager,
		AccessTokens:           accessTokens,
		Revocation:             memstore.NewRevocationStore(),
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  server.SystemClock{},
		Random:                 rand.Reader,
		IdentityClaims:         idp,
		FederationHTTP:         fetcher,
	}
	idp.srv, err = server.New(cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host, err)
	}
	idp.forgedBy, err = federation.NewTrustMarkIssuer(federation.TrustMarkIssueConfig{EntityID: id},
		federation.TrustMarkIssueDependencies{Signer: fedKey.signer, Algorithm: fapi.ES256, KeyID: fedKey.kid, Clock: federation.SystemClock{}})
	if err != nil {
		return nil, err
	}

	idp.entity = &entity{
		id: id, host: host, name: c.idpName, role: "national identity provider", country: c.key,
		key: fedKey, authorityHints: []string{ta.id},
		entityConfiguration: idp.entityConfiguration,
	}
	if err := w.add(idp.entity); err != nil {
		return nil, err
	}
	mux := idp.entity.mux
	mux.HandleFunc("GET /jwks", idp.jwks)
	mux.HandleFunc("POST /par", idp.par)
	mux.HandleFunc("GET "+authorizePath, idp.authorize)
	// The interaction handle cookie is SameSite, but a sibling host on the
	// same site (bank.southport.localhost next to id.southport.localhost)
	// still sends it. Refusing cross-origin POSTs is the CSRF defence
	// server.InteractionHandle's doc comment asks for.
	mux.Handle("POST "+authorizePath, http.NewCrossOriginProtection().Handler(http.HandlerFunc(idp.decide)))
	mux.HandleFunc("POST /token", idp.token)
	return idp, nil
}

// trustMark is the level-of-assurance mark this provider publishes: its
// accreditation body's, or — in the forge scene — one it signed itself.
func (p *identityProvider) trustMark() (federation.RawTrustMark, error) {
	if p.country.key == "eastmark" && p.w.scenes.ForgeEastmarkMark.Load() {
		jwt, err := p.forgedBy.TrustMark(federation.TrustMarkParams{Subject: p.entity.id, TrustMarkType: p.w.loaHighType, Lifetime: time.Hour})
		if err != nil {
			return federation.RawTrustMark{}, err
		}
		return federation.RawTrustMark{TrustMarkType: p.w.loaHighType, TrustMark: jwt}, nil
	}
	return p.w.accreditors[p.country.key].certify(p.entity.id)
}

// providerMetadata is the server's own metadata plus what only this
// provider knows: the scopes and identity claims it offers.
type providerMetadata struct {
	server.Metadata
	ScopesSupported []string `json:"scopes_supported"`
	ClaimsSupported []string `json:"claims_supported"`
}

// entityConfiguration is the provider's Entity Configuration: its OpenID
// Provider metadata, taken from the server, and its Trust Mark.
func (p *identityProvider) entityConfiguration(ctx context.Context) (string, error) {
	op, err := json.Marshal(providerMetadata{
		Metadata:        p.srv.Metadata(ctx),
		ScopesSupported: []string{"openid"},
		ClaimsSupported: []string{"sub", "given_name", "family_name", "birthdate", "email", "address", "nationality"},
	})
	if err != nil {
		return "", err
	}
	mark, err := p.trustMark()
	if err != nil {
		return "", err
	}
	return p.srv.EntityConfiguration(ctx, map[string]json.RawMessage{
		"openid_provider":   op,
		"federation_entity": p.entity.federationEntityMetadata(),
	}, mark)
}

// ResolveIdentityClaims implements server.IdentityClaimsSource: the
// approved claims of the citizen who signed in.
func (p *identityProvider) ResolveIdentityClaims(_ context.Context, subject string, names []string) (map[string]json.RawMessage, error) {
	for _, c := range p.country.citizens {
		if c.sub != subject {
			continue
		}
		all := c.claims(p.country.name)
		out := map[string]json.RawMessage{}
		for _, n := range names {
			if v, ok := all[n]; ok {
				out[n] = v
			}
		}
		return out, nil
	}
	return nil, nil
}

func (p *identityProvider) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := p.srv.PublicJWKS(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	set.WriteJSON(w)
}

func (p *identityProvider) par(w http.ResponseWriter, r *http.Request) {
	req, err := server.PushAuthorizationRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result, err := p.srv.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

func (p *identityProvider) token(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	if req.GrantType() != "authorization_code" {
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "only authorization_code is supported").WriteJSON(w)
		return
	}
	result, err := p.srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// authorize starts the interaction: it keeps the interaction handle in a
// cookie bound to this browser — never in the form — and renders the
// sign-in and consent page.
func (p *identityProvider) authorize(w http.ResponseWriter, r *http.Request) {
	// Local, never a redirect: an unreadable request names no
	// redirect URI it can be trusted with.
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		p.w.renderError(w, http.StatusBadRequest, "Sign-in could not start", publicMessage(err, "The sign-in request is malformed."))
		return
	}
	action, err := p.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		p.w.renderError(w, http.StatusInternalServerError, "Sign-in could not start", publicMessage(err, "Something went wrong. Please try again."))
		return
	}
	switch a := action.(type) {
	case server.InteractionRequired:
		// The consent page's state goes with the browser, encrypted, not
		// into this process; the page's form carries the tag that ties it
		// to this interaction.
		tag, err := p.interaction.Set(w, a, time.Now())
		if err != nil {
			p.w.renderError(w, http.StatusInternalServerError, "Sign-in could not start", publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		p.w.render(w, "consent", consentPage{
			Interaction: tag,
			Page:        p.w.page(p.country.idpName, p.country), Provider: p.country.idpName,
			// The name the service published about itself, from its Trust
			// Chain; shown with its entity ID, since the service chose it.
			Client: string(a.Interaction.ClientID), ClientName: clientName(a.Interaction),
			Scope: a.Interaction.Scope, Citizens: p.country.citizens,
			Claims: claimRows(a.Interaction.RequestedClaims),
		})
	case server.RedirectResponse:
		http.Redirect(w, r, a.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		p.w.renderError(w, a.Error.HTTPStatus(), "The sign-in request was rejected", string(a.Error.Code())+": "+a.Error.PublicDescription())
	}
}

// decide completes the interaction with the citizen chosen and the
// claims they agreed to share.
func (p *identityProvider) decide(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.w.renderError(w, http.StatusBadRequest, "Malformed form", formUnreadable)
		return
	}
	tag := r.PostForm.Get(interactioncookie.FormField)
	handle, interaction, err := p.interaction.Read(r, time.Now(), tag)
	if err != nil {
		p.w.renderError(w, http.StatusBadRequest, "Session expired", "This browser has no sign-in in progress.")
		return
	}

	var result server.InteractionResult
	if r.PostForm.Get("decision") != "approve" {
		result = server.Deny("the citizen declined")
	} else {
		sub := r.PostForm.Get("citizen")
		if !slices.ContainsFunc(p.country.citizens, func(c citizen) bool { return c.sub == sub }) {
			p.w.renderError(w, http.StatusBadRequest, "No citizen chosen", "Choose one of "+p.country.idpName+"'s citizens.")
			return
		}
		subjectID, err := server.NewSubjectID(sub)
		if err != nil {
			p.w.renderError(w, http.StatusBadRequest, "No citizen chosen", publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			p.w.renderError(w, http.StatusInternalServerError, signInFailed, publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		authCtx, err := server.NewAuthenticationContext(time.Now(), p.w.loaHighType, []string{"hwk"})
		if err != nil {
			p.w.renderError(w, http.StatusInternalServerError, signInFailed, publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		var approved []string
		for _, name := range r.PostForm["claim"] {
			if slices.Contains(interaction.RequestedClaims.Names(), name) {
				approved = append(approved, name)
			}
		}
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: interaction.Scope, ApprovedIdentityClaims: approved,
		})
	}

	p.interaction.Clear(w)
	outcome, err := p.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		p.w.renderError(w, http.StatusInternalServerError, signInFailed, publicMessage(err, "Something went wrong. Please try again."))
		return
	}
	switch o := outcome.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, o.Destination().String(), http.StatusFound)
	case server.AuthorizationLocalError:
		p.w.renderError(w, o.Error.HTTPStatus(), signInFailed, string(o.Error.Code())+": "+o.Error.PublicDescription())
	}
}

// clientName is what the consent page calls the service: its published
// client_name, or its entity ID if it published none.
func clientName(in server.InteractionRequest) string {
	if in.ClientDisplay.Name != "" {
		return in.ClientDisplay.Name
	}
	return string(in.ClientID)
}

// claimRow is one requested claim on the consent page.
type claimRow struct {
	Name, Label string
}

var claimLabels = map[string]string{
	"given_name": "Given name", "family_name": "Family name", "birthdate": "Date of birth",
	"email": "Email address", "address": "Home address", "nationality": "Nationality",
}

func claimRows(requested server.RequestedClaims) []claimRow {
	var rows []claimRow
	for _, name := range requested.Names() {
		label := claimLabels[name]
		if label == "" {
			label = name
		}
		rows = append(rows, claimRow{Name: name, Label: label})
	}
	return rows
}
