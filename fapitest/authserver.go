package fapitest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/metadata"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

const contentTypeJSON = "application/json"

// contentTypeHeader is the HTTP header name every JSON response this
// harness writes sets.
const contentTypeHeader = "Content-Type"

// AutoApprove is what the harness's authorization endpoint grants for
// every interaction, standing in for the real login/consent UI a
// production embedding application would render — fapitest exists to
// catch wire-protocol bugs, not to re-test the interaction UI server's
// own tests already cover in isolation.
type AutoApprove struct {
	Subject  string
	ACR      string
	AMR      []string
	AuthTime time.Time
}

// authServer wires a server.Server to real HTTP handlers over an
// httptest.Server, including the raw-request-boundary adapter
// (formRequestFromHTTP) and the interaction-auto-approval authorization
// endpoint AutoApprove describes.
type authServer struct {
	t        *testing.T
	srv      *server.Server
	resource *resource.Verifier
	clock    *manualClock
	approve  AutoApprove
	ts       *httptest.Server
}

// newAuthServer starts the HTTP listener before srv exists — its
// endpoint URLs (needed to construct srv) aren't known until the
// listener is bound to a real port. The handlers only dereference srv
// (and resource, once attached — see Harness.New) at request time, so
// it's safe to attach both afterward, before any test code makes a
// request; see Harness.attachServer.
//
// tlsClientCert selects a real TLS listener requesting (not requiring —
// every test that doesn't need one still uses this same server, just
// never presents a certificate) a client certificate, instead of the
// plain-HTTP httptest.Server every other Config uses. Needed whenever a
// certificate plays any role over the wire — sender-constraining
// (Config.SenderConstrain storage.SenderConstrainMTLS, checked only at
// token-issuance time — see peerCertificate's own doc comment) or
// certificate-based client authentication (Config.ClientAuthMethod's two
// RFC 8705 §2 values, checked at every endpoint that authenticates a
// client, including PAR).
func newAuthServer(t *testing.T, clock *manualClock, approve AutoApprove, tlsClientCert bool) *authServer {
	t.Helper()
	a := &authServer{t: t, clock: clock, approve: approve}
	mux := http.NewServeMux()
	mux.HandleFunc("/par", a.handlePAR)
	mux.HandleFunc("/authorize", a.handleAuthorize)
	mux.HandleFunc("/token", a.handleToken)
	mux.HandleFunc("/.well-known/openid-configuration", a.handleMetadata)
	mux.HandleFunc("/jwks", a.handleJWKS)
	mux.HandleFunc("/userinfo", a.handleUserInfo)
	if tlsClientCert {
		a.ts = httptest.NewUnstartedServer(mux)
		a.ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
		a.ts.StartTLS()
	} else {
		a.ts = httptest.NewServer(mux)
	}
	t.Cleanup(a.ts.Close)
	return a
}

// peerCertificate returns the first TLS client certificate presented
// on r's own connection, or nil if none was (including when the
// listener isn't TLS-capable at all — every Config that needs neither
// mTLS sender-constraining nor certificate-based client authentication).
// Threaded into handleToken (both grant branches) and handlePAR:
// sender-constraining binds at token-issuance time exclusively (RFC 8705
// §3 has no PAR-time pre-commitment concept the way DPoP's optional
// dpop_jkt does), but certificate-based client authentication (RFC 8705
// §2) is checked at every endpoint that authenticates a client, PAR
// included — a nil PeerCertificate is harmless when the registered
// client's ClientAuthMethod doesn't need one.
func peerCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// handleMetadata serves this authorization server's own metadata
// document — converting server.Metadata (a plain Go struct; server
// itself never owns HTTP or JSON wire encoding, see ARCHITECTURE.md
// design rule 6) into internal/metadata.Document's wire shape, the same
// conversion a real embedder's own discovery-endpoint handler would
// perform.
func (a *authServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	md := a.srv.Metadata(r.Context())
	doc := metadata.Document{
		Issuer:                                     md.Issuer.String(),
		AuthorizationEndpoint:                      md.AuthorizationEndpoint.String(),
		TokenEndpoint:                              md.TokenEndpoint.String(),
		PushedAuthorizationRequestEndpoint:         md.PushedAuthorizationRequestEndpoint.String(),
		JWKSURI:                                    md.JWKSURI.String(),
		ResponseTypesSupported:                     md.ResponseTypesSupported,
		ResponseModesSupported:                     md.ResponseModesSupported,
		GrantTypesSupported:                        md.GrantTypesSupported,
		SubjectTypesSupported:                      md.SubjectTypesSupported,
		CodeChallengeMethodsSupported:              md.CodeChallengeMethodsSupported,
		TokenEndpointAuthMethodsSupported:          md.TokenEndpointAuthMethodsSupported,
		TokenEndpointAuthSigningAlgValuesSupported: md.TokenEndpointAuthSigningAlgValuesSupported,
		RequestObjectSigningAlgValuesSupported:     md.RequestObjectSigningAlgValuesSupported,
		IDTokenSigningAlgValuesSupported:           md.IDTokenSigningAlgValuesSupported,
		AuthorizationSigningAlgValuesSupported:     md.AuthorizationSigningAlgValuesSupported,
		RequirePushedAuthorizationRequests:         md.RequirePushedAuthorizationRequests,
		RequireSignedRequestObject:                 md.RequireSignedRequestObject,
		AuthorizationResponseIssParameterSupported: md.AuthorizationResponseIssParameterSupported,
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		a.t.Fatalf("fapitest: encode metadata: %v", err)
	}
}

// handleJWKS serves this authorization server's own published keys.
func (a *authServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := a.srv.PublicJWKS(r.Context())
	if err != nil {
		a.t.Fatalf("fapitest: PublicJWKS: %v", err)
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(set); err != nil {
		a.t.Fatalf("fapitest: encode JWKS: %v", err)
	}
}

func (a *authServer) handlePAR(w http.ResponseWriter, r *http.Request) {
	form, err := formRequestFromHTTP(r)
	if err != nil {
		a.writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, pushErr := a.srv.PushAuthorizationRequest(r.Context(), server.PushAuthorizationRequest{HTTP: form, PeerCertificate: peerCertificate(r)})
	if pushErr != nil {
		a.writeServerError(w, pushErr)
		return
	}
	body, err := par.EncodeResult(par.PushResult{RequestURI: result.RequestURI.String(), ExpiresIn: result.ExpiresIn})
	if err != nil {
		a.t.Fatalf("fapitest: encode PAR result: %v", err)
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write(body); err != nil {
		a.t.Fatalf("fapitest: write PAR result: %v", err)
	}
}

func (a *authServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	action, err := a.srv.BeginAuthorization(ctx, server.BeginAuthorizationRequest{
		RequestURI: q.Get("request_uri"),
		ClientID:   clientIDFromQuery(q),
	})
	if err != nil {
		a.t.Fatalf("fapitest: BeginAuthorization: %v", err)
	}

	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		a.writeAuthorizationAction(w, action)
		return
	}

	subjectID, err := server.NewSubjectID(a.approve.Subject)
	if err != nil {
		a.t.Fatalf("fapitest: NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		a.t.Fatalf("fapitest: NewAuthenticatedSubject: %v", err)
	}
	authTime := a.approve.AuthTime
	if authTime.IsZero() {
		authTime = a.clock.Now()
	}
	authCtx, err := server.NewAuthenticationContext(authTime, a.approve.ACR, a.approve.AMR)
	if err != nil {
		a.t.Fatalf("fapitest: NewAuthenticationContext: %v", err)
	}

	result, err := a.srv.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: interaction.Interaction.Scope}),
	})
	if err != nil {
		a.t.Fatalf("fapitest: CompleteAuthorization: %v", err)
	}
	a.writeAuthorizationResult(w, result)
}

func (a *authServer) handleToken(w http.ResponseWriter, r *http.Request) {
	form, err := formRequestFromHTTP(r)
	if err != nil {
		a.writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	grantType := formValue(form, "grant_type")
	dpopProof := r.Header.Get("DPoP")
	peerCert := peerCertificate(r)

	var (
		result   server.TokenResult
		tokenErr error
	)
	switch grantType {
	case "authorization_code":
		result, tokenErr = a.srv.ExchangeAuthorizationCode(r.Context(), server.AuthorizationCodeExchangeRequest{HTTP: form, DPoPProof: dpopProof, PeerCertificate: peerCert})
	case "refresh_token":
		result, tokenErr = a.srv.RefreshAccessToken(r.Context(), server.RefreshTokenRequest{HTTP: form, DPoPProof: dpopProof, PeerCertificate: peerCert})
	default:
		a.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		return
	}
	if tokenErr != nil {
		a.writeServerError(w, tokenErr)
		return
	}

	resp := map[string]any{
		"access_token": result.AccessToken.Reveal(),
		"token_type":   result.TokenType,
		"expires_in":   int64(result.ExpiresIn / time.Second),
		"scope":        result.Scope,
	}
	if result.HasIDToken {
		resp["id_token"] = result.IDToken.Reveal()
	}
	if result.HasRefreshToken {
		resp["refresh_token"] = result.RefreshToken.Reveal()
	}
	if len(result.AuthorizationDetails) > 0 {
		resp["authorization_details"] = result.AuthorizationDetails
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		a.t.Fatalf("fapitest: encode token response: %v", err)
	}
}

// handleUserInfo serves a real, over-the-wire UserInfo endpoint backed
// by resource.Verifier — the same DPoP-proof and access-token
// verification a genuine resource server would apply, not a stand-in
// that trusts whatever client presents. It exists so a fapitest-based
// test can exercise client.FetchUserInfo's produced DPoP proof and
// Authorization header against real, independent verification, the way
// harness_test.go's own verifyAccessToken already does for a
// hand-built request — catching a wire-format bug FetchUserInfo's own
// unit tests (which never verify the proof at all) cannot see. The
// response is always plain, unsigned JSON: signed and encrypted
// UserInfo responses are already covered at the unit level in
// client/userinfo_test.go, and this handler's job is the transport, not
// re-proving that.
func (a *authServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authz, err := a.resource.Verify(r.Context(), resource.VerifyRequest{
		Method:        r.Method,
		URL:           requestURL(r, a.ts.URL),
		Authorization: r.Header.Get("Authorization"),
		DPoPProof:     r.Header.Get("DPoP"),
	})
	if err != nil {
		a.writeResourceError(w, err)
		return
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{"sub": authz.Subject}); err != nil {
		a.t.Fatalf("fapitest: encode userinfo response: %v", err)
	}
}

// requestURL reconstructs the absolute URL r was made against —
// resource.VerifyRequest.URL must be absolute (it's compared against
// the DPoP proof's own "htu" claim, itself always absolute), but an
// http.Request's own r.URL is request-target-relative for a real server
// listener.
func requestURL(r *http.Request, base string) *url.URL {
	u, err := url.Parse(base)
	if err != nil {
		panic(fmt.Sprintf("fapitest: parse base url: %v", err))
	}
	u.Path = r.URL.Path
	u.RawQuery = r.URL.RawQuery
	return u
}

func (a *authServer) writeResourceError(w http.ResponseWriter, err error) {
	rerr, ok := err.(*resource.Error)
	if !ok {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`DPoP error=%q`, rerr.Code()))
	a.writeOAuthError(w, rerr.HTTPStatus(), string(rerr.Code()), rerr.PublicDescription())
}

func (a *authServer) writeAuthorizationAction(w http.ResponseWriter, action server.AuthorizationAction) {
	switch v := action.(type) {
	case server.RedirectResponse:
		w.Header().Set("Location", v.Destination.String())
		w.WriteHeader(http.StatusFound)
	case server.LocalErrorResponse:
		a.writeServerError(w, v.Error)
	default:
		a.t.Fatalf("fapitest: unrecognized AuthorizationAction %T", action)
	}
}

func (a *authServer) writeAuthorizationResult(w http.ResponseWriter, result server.AuthorizationResult) {
	switch v := result.(type) {
	case server.AuthorizationRedirect:
		w.Header().Set("Location", v.Destination().String())
		w.WriteHeader(http.StatusFound)
	case server.AuthorizationLocalError:
		a.writeServerError(w, v.Error)
	default:
		a.t.Fatalf("fapitest: unrecognized AuthorizationResult %T", result)
	}
}

func (a *authServer) writeServerError(w http.ResponseWriter, err error) {
	srvErr, ok := asServerError(err)
	if !ok {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.writeOAuthError(w, srvErr.HTTPStatus(), string(srvErr.Code()), srvErr.PublicDescription())
}

func (a *authServer) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	body, err := par.EncodeErrorResponse(par.ErrorResponse{Code: code, Description: description})
	if err != nil {
		a.t.Fatalf("fapitest: encode error response: %v", err)
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		a.t.Fatalf("fapitest: write error response: %v", err)
	}
}

func asServerError(err error) (*server.Error, bool) {
	srvErr, ok := err.(*server.Error)
	return srvErr, ok
}

func clientIDFromQuery(q url.Values) fapi.ClientID {
	return fapi.ClientID(q.Get("client_id"))
}

func formValue(form server.FormRequest, name string) string {
	for _, p := range form.Parameters {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// manualClock lets the harness advance time deterministically; both the
// simulated authorization server and, if the test wants, assertions
// about token lifetimes can rely on it instead of wall-clock time.
type manualClock struct {
	now time.Time
}

func (c *manualClock) Now() time.Time { return c.now }

func (c *manualClock) Advance(d time.Duration) { c.now = c.now.Add(d) }
