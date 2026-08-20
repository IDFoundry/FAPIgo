package fapitest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/metadata"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/server"
)

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
	t       *testing.T
	srv     *server.Server
	clock   *manualClock
	approve AutoApprove
	ts      *httptest.Server
}

// newAuthServer starts the HTTP listener before srv exists — its
// endpoint URLs (needed to construct srv) aren't known until the
// listener is bound to a real port. The handlers only dereference srv at
// request time, so it's safe to attach it afterward, before any test
// code makes a request; see Harness.attachServer.
func newAuthServer(t *testing.T, clock *manualClock, approve AutoApprove) *authServer {
	t.Helper()
	a := &authServer{t: t, clock: clock, approve: approve}
	mux := http.NewServeMux()
	mux.HandleFunc("/par", a.handlePAR)
	mux.HandleFunc("/authorize", a.handleAuthorize)
	mux.HandleFunc("/token", a.handleToken)
	mux.HandleFunc("/.well-known/openid-configuration", a.handleMetadata)
	mux.HandleFunc("/jwks", a.handleJWKS)
	a.ts = httptest.NewServer(mux)
	t.Cleanup(a.ts.Close)
	return a
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
	w.Header().Set("Content-Type", "application/json")
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
	w.Header().Set("Content-Type", "application/json")
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
	result, pushErr := a.srv.PushAuthorizationRequest(r.Context(), server.PushAuthorizationRequest{HTTP: form})
	if pushErr != nil {
		a.writeServerError(w, pushErr)
		return
	}
	body, err := par.EncodeResult(par.PushResult{RequestURI: result.RequestURI.String(), ExpiresIn: result.ExpiresIn})
	if err != nil {
		a.t.Fatalf("fapitest: encode PAR result: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
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

	var (
		result   server.TokenResult
		tokenErr error
	)
	switch grantType {
	case "authorization_code":
		result, tokenErr = a.srv.ExchangeAuthorizationCode(r.Context(), server.AuthorizationCodeExchangeRequest{HTTP: form, DPoPProof: dpopProof})
	case "refresh_token":
		result, tokenErr = a.srv.RefreshAccessToken(r.Context(), server.RefreshTokenRequest{HTTP: form, DPoPProof: dpopProof})
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
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		a.t.Fatalf("fapitest: encode token response: %v", err)
	}
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
	w.Header().Set("Content-Type", "application/json")
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
