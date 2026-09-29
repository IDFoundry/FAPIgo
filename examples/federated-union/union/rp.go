package union

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// requestedClaims is what every service asks each citizen to share.
var requestedClaims = client.RequestedClaims{
	IDToken: []string{"given_name", "family_name", "birthdate", "nationality", "address"},
}

// relyingParty is a service in one Union country that accepts citizens
// of every country, discovering and trusting their identity providers
// through the federation alone.
type relyingParty struct {
	entity   *entity
	country  country
	w        *World
	resolver *federation.Resolver
	keys     keys.KeyManager
	authJWKS json.RawMessage
	sessions storage.SessionStore
	redirect string

	mu      sync.Mutex
	clients map[string]*client.Client // by identity provider entity ID
}

const (
	noSignIn       = "No sign-in in progress"
	sessionCookie  = "fu_session"
	providerCookie = "fu_provider"
)

func (w *World) newRelyingParty(s serviceSpec) (*relyingParty, error) {
	c := countryByKey(s.country)
	fedKey, err := newSigningKey(c.key+"-"+s.host+"-fed-1", keys.FederationEntitySigning)
	if err != nil {
		return nil, err
	}
	authKey, err := newSigningKey(s.host+"-auth-1", keys.ClientAuthentication)
	if err != nil {
		return nil, err
	}
	dpop, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return nil, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		// OpenID Federation 1.0 §12.1.1.1: the request object is signed
		// with a key from the RP's own published JWK Set, the same one
		// its client assertions use.
		map[keys.SigningPurpose]crypto.Signer{
			keys.ClientAuthentication: authKey.signer, keys.RequestObjectSigning: authKey.signer, keys.DPoPProofSigning: dpop,
		},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{
			keys.ClientAuthentication: fapi.ES256, keys.RequestObjectSigning: fapi.ES256, keys.DPoPProofSigning: fapi.ES256,
		},
		map[keys.SigningPurpose]string{
			keys.ClientAuthentication: authKey.kid, keys.RequestObjectSigning: authKey.kid,
		},
	)
	if err != nil {
		return nil, err
	}

	rp := &relyingParty{
		country: c, w: w, keys: manager, authJWKS: authKey.jwks,
		sessions: memstore.NewSessionStore(), clients: map[string]*client.Client{},
	}
	rp.entity = &entity{
		id: w.entityID(s.host), host: s.host, name: s.name, role: "service", country: c.key,
		key: fedKey, authorityHints: []string{w.authorities[c.key].id},
		metadata: rp.metadata,
	}
	rp.redirect = rp.entity.id + "/callback"
	if err := w.add(rp.entity); err != nil {
		return nil, err
	}
	// A service trusts the Union and its own country's authority.
	rp.resolver, err = w.resolverFor(s.host, w.union, w.authorities[c.key])
	if err != nil {
		return nil, err
	}
	mux := rp.entity.mux
	mux.HandleFunc("GET /{$}", rp.home)
	mux.HandleFunc("GET /login", rp.login)
	mux.HandleFunc("GET /callback", rp.callback)
	return rp, nil
}

// metadata is the service's openid_relying_party metadata. It declares
// more grant types than the Union allows, so the console can show the
// Union's policy narrowing them.
func (rp *relyingParty) metadata(context.Context) (map[string]json.RawMessage, error) {
	md, err := json.Marshal(federation.OpenIDRelyingPartyMetadata{ //nolint:gosec // "private_key_jwt" names an auth method, not a secret
		ClientRegistrationTypes:     []string{"automatic"},
		ResponseTypes:               []string{"code"},
		RedirectURIs:                []string{rp.redirect},
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: fapi.ES256.String(),
		RequestObjectSigningAlg:     fapi.ES256.String(),
		JWKS:                        rp.authJWKS,
		ClientName:                  rp.entity.name,
		Contacts:                    []string{"federation@" + rp.entity.host},
	})
	if err != nil {
		return nil, err
	}
	var withGrants map[string]any
	if err := json.Unmarshal(md, &withGrants); err != nil {
		return nil, err
	}
	withGrants["grant_types"] = []string{"authorization_code", "refresh_token", "client_credentials"}
	raw, err := json.Marshal(withGrants)
	if err != nil {
		return nil, err
	}
	return map[string]json.RawMessage{"openid_relying_party": raw}, nil
}

// providerStatus is how one identity provider looks from this service.
type providerStatus struct {
	ID, Name, Country, Color string
	Chain                    []string
	Reachable                bool
	Problem                  string
	LoAHigh                  bool
	LoAProblem               string
	LoAIssuer                string
}

// assess resolves provider's Trust Chain from this service and checks its
// level-of-assurance Trust Mark, requiring the Union's accreditation of
// the mark's issuer.
func (rp *relyingParty) assess(ctx context.Context, idp *identityProvider) providerStatus {
	st := providerStatus{ID: idp.entity.id, Name: idp.country.idpName, Country: idp.country.name, Color: idp.country.color}
	resolved, err := rp.resolver.Resolve(ctx, idp.entity.id)
	if err != nil {
		st.Problem = err.Error()
		return st
	}
	st.Reachable = true
	st.Chain = resolved.Chain
	st.LoAProblem = "publishes no level-of-assurance mark"
	for _, mark := range resolved.TrustMarks {
		if mark.TrustMarkType != rp.w.loaHighType {
			continue
		}
		claims, err := rp.resolver.VerifyTrustMark(ctx, idp.entity.id, mark, federation.RequireFederationAccreditation)
		if err != nil {
			st.LoAProblem = err.Error()
			continue
		}
		st.LoAHigh, st.LoAProblem, st.LoAIssuer = true, "", claims.Issuer
		break
	}
	return st
}

func (rp *relyingParty) home(w http.ResponseWriter, r *http.Request) {
	var providers []providerStatus
	for _, c := range countries {
		providers = append(providers, rp.assess(r.Context(), rp.w.idps[c.key]))
	}
	sort.SliceStable(providers, func(i, j int) bool {
		return providers[i].Country == rp.country.name && providers[j].Country != rp.country.name
	})
	rp.w.render(w, "service", servicePage{Page: rp.w.page(rp.entity.name, rp.country), Providers: providers, Requested: requestedClaims.IDToken})
}

// clientFor discovers provider through the federation and builds a
// client for it, identified by this service's own Entity Identifier —
// no registration with the provider beforehand.
func (rp *relyingParty) clientFor(ctx context.Context, provider string) (*client.Client, error) {
	discovered, err := client.DiscoverViaFederation(ctx, rp.resolver, provider)
	if err != nil {
		return nil, err
	}
	fetcher, err := rp.w.fetcher(rp.entity.host)
	if err != nil {
		return nil, err
	}
	issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, discovered.JWKSURI, time.Minute)
	if err != nil {
		return nil, err
	}
	issuer, err := fapi.ParseIssuerURL(provider)
	if err != nil {
		return nil, err
	}
	cl, err := client.NewFromDiscovery(discovered, client.Config{
		Issuer:      issuer,
		Endpoints:   discovered.Endpoints,
		ClientID:    fapi.ClientID(rp.entity.id),
		RedirectURI: rp.redirect,
		Profile:     client.ProfileFAPISecurity,
		Assurance:   client.AssuranceDevelopment,
		// A service registered automatically proves control of its keys
		// with a signed request object (OpenID Federation 1.0 §12.1.1.1).
		PushedRequestEncoding:          client.PushedRequestEncodingRequestObject,
		AuthorizationResponseIssPolicy: client.TolerateAbsentAuthorizationResponseIss,
		Algorithms: client.Algorithms{
			DPoP: fapi.ES256, IDToken: fapi.ES256, ClientAuthentication: fapi.ES256, RequestObject: fapi.ES256,
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute, RequestObjectLifetime: time.Minute,
			SessionLifetime: 10 * time.Minute, MaxIDTokenLifetime: 10 * time.Minute,
			MaxClockSkew: 30 * time.Second, HTTPTimeout: 10 * time.Second,
			MaxHTTPResponseBytes: 1 << 20, MaxJOSECompactBytes: 16 * 1024,
		},
	}, client.Dependencies{
		Sessions: rp.sessions, Keys: rp.keys, IssuerKeys: issuerKeys,
		HTTP: rp.w.net.Client(rp.entity.host), Clock: client.SystemClock{}, Random: rand.Reader,
	})
	if err != nil {
		return nil, err
	}
	rp.mu.Lock()
	rp.clients[provider] = cl
	rp.mu.Unlock()
	return cl, nil
}

func (rp *relyingParty) login(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	idp := rp.w.idpByID(provider)
	if idp == nil {
		rp.w.renderError(w, http.StatusBadRequest, "Unknown identity provider", provider)
		return
	}
	status := rp.assess(r.Context(), idp)
	if !status.Reachable {
		rp.w.renderError(w, http.StatusForbidden, idp.country.idpName+" is not trusted", status.Problem)
		return
	}
	if !status.LoAHigh {
		rp.w.renderError(w, http.StatusForbidden, idp.country.idpName+" is not accredited at a high level of assurance", status.LoAProblem)
		return
	}
	cl, err := rp.clientFor(r.Context(), provider)
	if err != nil {
		rp.w.renderError(w, http.StatusBadGateway, "Could not discover "+idp.country.idpName, err.Error())
		return
	}
	session, err := cl.BeginAuthorization(r.Context(), client.BeginAuthorizationRequest{
		Scope: []string{"openid"}, Claims: requestedClaims,
	})
	if err != nil {
		rp.w.renderError(w, http.StatusBadGateway, idp.country.idpName+" refused the sign-in request", err.Error())
		return
	}
	// The session handle binds the callback to this browser (RFC 9700
	// §4.7): the callback is only accepted alongside this cookie.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session.Handle().String(), Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: providerCookie, Value: provider, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	u := session.URL()
	// Not an open redirect: provider must be one of the demo's own
	// identity providers (idpByID above), and the URL is its
	// authorization endpoint, from Trust-Chain-verified metadata.
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: see above

}

func (rp *relyingParty) callback(w http.ResponseWriter, r *http.Request) {
	sessionC, err1 := r.Cookie(sessionCookie)
	providerC, err2 := r.Cookie(providerCookie)
	if err1 != nil || err2 != nil {
		rp.w.renderError(w, http.StatusBadRequest, noSignIn, "This browser didn't start a sign-in here.")
		return
	}
	handle, err := client.ParseSessionHandle(sessionC.Value)
	if err != nil {
		rp.w.renderError(w, http.StatusBadRequest, noSignIn, err.Error())
		return
	}
	rp.mu.Lock()
	cl := rp.clients[providerC.Value]
	rp.mu.Unlock()
	if cl == nil {
		rp.w.renderError(w, http.StatusBadRequest, noSignIn, "Unknown identity provider.")
		return
	}
	result, err := cl.CompleteAuthorization(r.Context(), client.AuthorizationCallback{RawQuery: r.URL.RawQuery, Session: handle})
	if err != nil {
		rp.w.renderError(w, http.StatusBadGateway, signInFailed, err.Error())
		return
	}
	idp := rp.w.idpByID(providerC.Value)
	switch res := result.(type) {
	case client.CompletionSuccess:
		claims := res.Tokens.IDTokenClaims
		var shared []sharedClaim
		for _, name := range requestedClaims.IDToken {
			row := sharedClaim{Label: claimLabels[name]}
			if raw, ok := claims.Parameters[name]; ok {
				row.Value, row.Shared = displayClaim(raw), true
			}
			shared = append(shared, row)
		}
		rp.w.render(w, "welcome", welcomePage{
			Page: rp.w.page(rp.entity.name, rp.country), Provider: idp.country.idpName, ProviderCountry: idp.country.name,
			Subject: res.Tokens.Subject, Issuer: claims.Issuer, Claims: shared,
			CrossBorder: idp.country.key != rp.country.key,
		})
	case client.CompletionDenied:
		rp.w.renderError(w, http.StatusForbidden, "Sign-in declined", res.Code+": "+res.Description)
	default:
		rp.w.renderError(w, http.StatusBadGateway, signInFailed, fmt.Sprintf("unexpected result %T", result))
	}
}

// sharedClaim is one requested claim on the welcome page.
type sharedClaim struct {
	Label, Value string
	Shared       bool
}

// displayClaim renders a JSON claim value for the page: a string as-is,
// an address by its formatted form.
func displayClaim(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var addr struct {
		Formatted string `json:"formatted"`
	}
	if json.Unmarshal(raw, &addr) == nil && addr.Formatted != "" {
		return addr.Formatted
	}
	return string(raw)
}

func (w *World) idpByID(id string) *identityProvider {
	for _, p := range w.idps {
		if p.entity.id == id {
			return p
		}
	}
	return nil
}

// displayName is the organisation name of the entity with id, for pages.
func (w *World) displayName(id string) string {
	for _, e := range w.entities {
		if e.id == id {
			return e.name
		}
	}
	return id
}
