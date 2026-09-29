package union

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
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

	mu      sync.Mutex
	pending map[string]pendingLogin // by interaction handle
}

// pendingLogin is what the consent page needs back when it's submitted.
type pendingLogin struct {
	handle      server.InteractionHandle
	interaction server.InteractionRequest
}

const interactionCookie = "fu_interaction"

func (w *World) newIdentityProvider(c country, ta *entity) (*identityProvider, error) {
	host := "id." + c.key + ".localhost"
	id := w.entityID(host)
	issuer, err := fapi.ParseIssuerURL(id)
	if err != nil {
		return nil, err
	}
	endpoint := func(path string) (fapi.URL, error) { return fapi.ParseEndpointURL(id + path) }
	authz, err := endpoint("/authorize")
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
		},
	}
	idp := &identityProvider{country: c, fedKey: fedKey, w: w, pending: map[string]pendingLogin{}}
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
	mux.HandleFunc("GET /authorize", idp.authorize)
	mux.HandleFunc("POST /authorize", idp.decide)
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

// entityConfiguration is the provider's Entity Configuration: its OpenID
// Provider metadata, taken from the server, and its Trust Mark.
func (p *identityProvider) entityConfiguration(ctx context.Context) (string, error) {
	md, err := json.Marshal(p.srv.Metadata(ctx))
	if err != nil {
		return "", err
	}
	var op map[string]any
	if err := json.Unmarshal(md, &op); err != nil {
		return "", err
	}
	op["client_registration_types_supported"] = []string{"automatic"}
	op["claims_parameter_supported"] = true
	op["scopes_supported"] = []string{"openid"}
	op["claims_supported"] = []string{"sub", "given_name", "family_name", "birthdate", "email", "address", "nationality"}
	opRaw, err := json.Marshal(op)
	if err != nil {
		return "", err
	}
	mark, err := p.trustMark()
	if err != nil {
		return "", err
	}
	return p.srv.EntityConfiguration(ctx, map[string]json.RawMessage{
		"openid_provider":   opRaw,
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (p *identityProvider) par(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	result, err := p.srv.PushAuthorizationRequest(r.Context(), server.PushAuthorizationRequest{
		HTTP: form, DPoPProofs: r.Header.Values("DPoP"),
	})
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

func (p *identityProvider) token(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	if form.Get("grant_type") != "authorization_code" {
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "only authorization_code is supported").WriteJSON(w)
		return
	}
	result, err := p.srv.ExchangeAuthorizationCode(r.Context(), server.AuthorizationCodeExchangeRequest{
		HTTP: form, DPoPProofs: r.Header.Values("DPoP"),
	})
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
	q := r.URL.Query()
	action, err := p.srv.BeginAuthorization(r.Context(), server.BeginAuthorizationRequest{
		RequestURI: q.Get("request_uri"), ClientID: fapi.ClientID(q.Get("client_id")),
	})
	if err != nil {
		p.w.renderError(w, http.StatusInternalServerError, "Sign-in could not start", err.Error())
		return
	}
	switch a := action.(type) {
	case server.InteractionRequired:
		p.mu.Lock()
		p.pending[a.Handle.String()] = pendingLogin{handle: a.Handle, interaction: a.Interaction}
		p.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name: interactionCookie, Value: a.Handle.String(), Path: "/authorize",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		p.w.render(w, "consent", consentPage{
			Page: p.w.page(p.country.idpName, p.country), Provider: p.country.idpName,
			Client: string(a.Interaction.ClientID), ClientName: p.w.displayName(string(a.Interaction.ClientID)),
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
	cookie, err := r.Cookie(interactionCookie)
	if err != nil {
		p.w.renderError(w, http.StatusBadRequest, "Session expired", "This browser has no sign-in in progress.")
		return
	}
	p.mu.Lock()
	login, ok := p.pending[cookie.Value]
	delete(p.pending, cookie.Value)
	p.mu.Unlock()
	if !ok {
		p.w.renderError(w, http.StatusBadRequest, "Session expired", "The sign-in in progress is unknown or already finished.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: interactionCookie, Path: "/authorize", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	if err := r.ParseForm(); err != nil {
		p.w.renderError(w, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}

	var result server.InteractionResult
	if r.PostForm.Get("decision") != "approve" {
		result = server.Deny("the citizen declined")
	} else {
		subjectID, err := server.NewSubjectID(r.PostForm.Get("citizen"))
		if err != nil {
			p.w.renderError(w, http.StatusBadRequest, "No citizen chosen", err.Error())
			return
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			p.w.renderError(w, http.StatusInternalServerError, "Sign-in failed", err.Error())
			return
		}
		authCtx, err := server.NewAuthenticationContext(time.Now(), "https://union.localhost/loa/high", []string{"hwk"})
		if err != nil {
			p.w.renderError(w, http.StatusInternalServerError, "Sign-in failed", err.Error())
			return
		}
		var approved []string
		for _, name := range r.PostForm["claim"] {
			if slices.Contains(login.interaction.RequestedClaims.Names(), name) {
				approved = append(approved, name)
			}
		}
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: login.interaction.Scope, ApprovedIdentityClaims: approved,
		})
	}

	outcome, err := p.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: login.handle, Result: result})
	if err != nil {
		p.w.renderError(w, http.StatusInternalServerError, "Sign-in failed", err.Error())
		return
	}
	switch o := outcome.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, o.Destination().String(), http.StatusFound)
	case server.AuthorizationLocalError:
		p.w.renderError(w, o.Error.HTTPStatus(), "Sign-in failed", string(o.Error.Code())+": "+o.Error.PublicDescription())
	}
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
