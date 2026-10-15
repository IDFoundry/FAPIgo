package fapitest_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
)

// The resource servers the RFC 8707 tests' authorization server serves.
const (
	payments    = "https://payments.fapitest.internal"
	accounts    = "https://accounts.fapitest.internal/v1"
	credentials = "https://credentials.fapitest.internal"
	// unlisted is a resource the server neither lists nor accepts.
	unlisted = "https://elsewhere.fapitest.internal"
)

var servedResources = []string{payments, accounts, credentials}

// TestResourceIndicators drives RFC 8707 resource indicators from a real
// client.Client through a real server.Server to real resource
// verifiers, under both profiles (plain PAR form parameters, and a
// signed request object) and both access-token formats: the access
// token is issued for exactly the requested resources, and each
// resource server accepts it only when it is one of them.
func TestResourceIndicators(t *testing.T) {
	for _, profile := range []struct {
		name    string
		profile server.Profile
	}{
		{"PAR form", server.ProfileFAPISecurity},
		{"request object", server.ProfileFAPISecurityWithMessageSigning},
	} {
		for _, format := range []struct {
			name   string
			opaque bool
		}{{"JWT", false}, {"opaque", true}} {
			t.Run(profile.name+"/"+format.name, func(t *testing.T) {
				h := fapitest.New(t, fapitest.Config{Profile: profile.profile, Resources: servedResources, OpaqueAccessTokens: format.opaque})
				ctx := context.Background()

				t.Run("several resources", func(t *testing.T) {
					tokens := runResourceFlow(t, h, []string{payments, accounts})
					if !slices.Equal(tokens.Resource, []string{payments, accounts}) {
						t.Errorf("TokenSet.Resource = %q, want both requested resources", tokens.Resource)
					}
					if !format.opaque {
						checkJWTAudience(t, tokens, `["`+payments+`","`+accounts+`"]`)
					}
					checkVerifierAudience(t, h, tokens, payments, []string{payments, accounts})
					checkVerifierAudience(t, h, tokens, accounts, []string{payments, accounts})
					refuseAtResource(t, h, tokens, serverresource.Options{Resource: credentials})
					refuseAtResource(t, h, tokens, serverresource.Options{Resource: unlisted})
					refuseAtResource(t, h, tokens, serverresource.Options{Resource: credentials, AcceptIssuerAudience: true})
					// The issuer's own resource server (UserInfo, say)
					// isn't one of them either.
					refuseAt(t, h, h.Resource, tokens)
				})

				t.Run("one resource", func(t *testing.T) {
					tokens := runResourceFlow(t, h, []string{credentials})
					if !format.opaque {
						checkJWTAudience(t, tokens, `"`+credentials+`"`)
					}
					checkVerifierAudience(t, h, tokens, credentials, []string{credentials})
					refuseAtResource(t, h, tokens, serverresource.Options{Resource: payments})
				})

				t.Run("no resource", func(t *testing.T) {
					tokens, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
					if err != nil {
						t.Fatalf("RunAuthorizationCodeFlow: %v", err)
					}
					if !format.opaque {
						checkJWTAudience(t, tokens, `"`+fapitest.Issuer+`"`)
					}
					// Addressed to the issuer: accepted there, refused by a
					// resource server that requires its own identifier,
					// and accepted by one migrating with
					// AcceptIssuerAudience.
					verifyAt(t, h, h.Resource, tokens)
					refuseAtResource(t, h, tokens, serverresource.Options{Resource: payments})
					v, err := h.NewResourceVerifier(serverresource.Options{Resource: payments, AcceptIssuerAudience: true})
					if err != nil {
						t.Fatalf("NewResourceVerifier(AcceptIssuerAudience): %v", err)
					}
					verifyAt(t, h, v, tokens)
				})
			})
		}
	}
}

// TestResourceIndicatorsRefresh narrows a refresh to some of the
// original resources, end to end, and shows a refresh can't widen them:
// the client refuses before sending, and the server refuses a token set
// edited to claim more.
func TestResourceIndicatorsRefresh(t *testing.T) {
	for _, opaque := range []bool{false, true} {
		t.Run(fmt.Sprintf("opaque=%v", opaque), func(t *testing.T) {
			h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, Resources: servedResources, OpaqueAccessTokens: opaque})
			ctx := context.Background()
			first := runResourceFlow(t, h, []string{payments, accounts})

			// No Resource: the refresh names the original ones again.
			again, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first})
			if err != nil {
				t.Fatalf("RefreshTokens: %v", err)
			}
			if !slices.Equal(again.Resource, []string{payments, accounts}) {
				t.Errorf("refreshed Resource = %q, want the original resources", again.Resource)
			}
			checkVerifierAudience(t, h, again, accounts, []string{payments, accounts})

			narrowed, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first, Resource: []string{accounts}})
			if err != nil {
				t.Fatalf("RefreshTokens(narrowed): %v", err)
			}
			if !slices.Equal(narrowed.Resource, []string{accounts}) {
				t.Errorf("narrowed Resource = %q, want %q", narrowed.Resource, accounts)
			}
			if !opaque {
				checkJWTAudience(t, narrowed, `"`+accounts+`"`)
			}
			checkVerifierAudience(t, h, narrowed, accounts, []string{accounts})
			refuseAtResource(t, h, narrowed, serverresource.Options{Resource: payments})

			// Narrowing one refresh doesn't narrow the grant: the
			// original token set still refreshes for its other resource.
			if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first, Resource: []string{payments}}); err != nil {
				t.Errorf("RefreshTokens(the other original resource): %v", err)
			}

			// Widening: the client refuses a resource the tokens weren't
			// issued for, without asking the server...
			_, err = h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first, Resource: []string{payments, credentials}})
			var cerr *client.Error
			if !errors.As(err, &cerr) {
				t.Fatalf("RefreshTokens(widened) = %v, want a *client.Error", err)
			}
			if _, fromServer := cerr.ServerResponse(); fromServer {
				t.Errorf("RefreshTokens(widened) was refused by the server, want the client to refuse it before sending")
			}

			// ...and the server refuses one sent anyway, from a token
			// set edited to claim a resource the grant never had.
			edited := first
			edited.Resource = []string{payments, accounts, credentials}
			_, err = h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: edited})
			wantServerError(t, "RefreshTokens(edited token set)", err, "invalid_target")
		})
	}
}

// TestResourceIndicatorsRefused surfaces the server's invalid_target
// through the client's error, for a resource the server doesn't serve
// and for one its client isn't registered for.
func TestResourceIndicatorsRefused(t *testing.T) {
	for _, profile := range []server.Profile{server.ProfileFAPISecurity, server.ProfileFAPISecurityWithMessageSigning} {
		t.Run(profileName(profile), func(t *testing.T) {
			// The client may name unlisted, but the server doesn't serve
			// it; the server serves credentials, but the client may not
			// name it.
			h := fapitest.New(t, fapitest.Config{Profile: profile, Resources: servedResources, AllowedResources: []string{payments, accounts, unlisted}})
			ctx := context.Background()
			for _, tc := range []struct {
				name      string
				resources []string
			}{
				{"not served", []string{payments, unlisted}},
				{"not allowed for the client", []string{credentials}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					_, err := h.RunAuthorizationCodeFlowWithRequest(ctx, client.BeginAuthorizationRequest{Scope: offlineScope, Resource: tc.resources})
					wantServerError(t, "RunAuthorizationCodeFlowWithRequest", err, "invalid_target")
				})
			}
			// And a resource the client may request still works.
			checkVerifierAudience(t, h, runResourceFlow(t, h, []string{accounts}), accounts, []string{accounts})
		})
	}
}

// TestResourceIndicatorsPolicy decides resources Config.Resources
// doesn't list with a ResourcePolicy, end to end: it's asked about only
// the unlisted ones, an accepted resource reaches the token's audience,
// a refusal is invalid_target, and a failure to decide is server_error.
func TestResourceIndicatorsPolicy(t *testing.T) {
	policy := &recordingPolicy{allow: credentials, fail: "https://broken.fapitest.internal"}
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, Resources: []string{payments}, ResourcePolicy: policy})
	ctx := context.Background()

	tokens := runResourceFlow(t, h, []string{payments, credentials})
	checkVerifierAudience(t, h, tokens, credentials, []string{payments, credentials})
	for _, asked := range policy.asked() {
		if !slices.Equal(asked, []string{credentials}) {
			t.Errorf("ResourcePolicy asked about %q, want only the unlisted %q", asked, credentials)
		}
	}
	if len(policy.asked()) == 0 {
		t.Error("ResourcePolicy was never asked about the unlisted resource")
	}

	_, err := h.RunAuthorizationCodeFlowWithRequest(ctx, client.BeginAuthorizationRequest{Scope: offlineScope, Resource: []string{payments, unlisted}})
	wantServerError(t, "refused by the policy", err, "invalid_target")
	_, err = h.RunAuthorizationCodeFlowWithRequest(ctx, client.BeginAuthorizationRequest{Scope: offlineScope, Resource: []string{policy.fail}})
	wantServerError(t, "policy failure", err, "server_error")
}

// recordingPolicy accepts allow, fails to decide fail, refuses anything
// else, and records what it was asked.
type recordingPolicy struct {
	allow, fail string

	mu    sync.Mutex
	calls [][]string
}

func (p *recordingPolicy) AllowResources(_ context.Context, _ storage.RegisteredClient, resources []string) error {
	p.mu.Lock()
	p.calls = append(p.calls, slices.Clone(resources))
	p.mu.Unlock()
	for _, r := range resources {
		switch r {
		case p.allow:
		case p.fail:
			return errors.New("policy store unavailable")
		default:
			return fmt.Errorf("%q: %w", r, server.ErrResourceNotAllowed)
		}
	}
	return nil
}

func (p *recordingPolicy) asked() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

func profileName(p server.Profile) string {
	if p == server.ProfileFAPISecurityWithMessageSigning {
		return "request object"
	}
	return "PAR form"
}

// runResourceFlow runs an authorization_code flow requesting resources.
func runResourceFlow(t *testing.T, h *fapitest.Harness, resources []string) client.TokenSet {
	t.Helper()
	tokens, err := h.RunAuthorizationCodeFlowWithRequest(context.Background(), client.BeginAuthorizationRequest{Scope: offlineScope, Resource: resources})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlowWithRequest(Resource %q): %v", resources, err)
	}
	return tokens
}

// checkJWTAudience checks the JWT access token's "aud" is exactly
// wantJSON: a string for one audience, an array for several.
func checkJWTAudience(t *testing.T, tokens client.TokenSet, wantJSON string) {
	t.Helper()
	parts := strings.Split(tokens.AccessToken.Reveal(), ".")
	if len(parts) != 3 {
		t.Fatalf("access token has %d parts, want a JWS", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access token payload: %v", err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal access token payload: %v", err)
	}
	if got := string(claims["aud"]); got != wantJSON {
		t.Errorf("access token aud = %s, want %s", got, wantJSON)
	}
}

// checkVerifierAudience verifies tokens at the resource server for
// resourceID and checks the audience it reports.
func checkVerifierAudience(t *testing.T, h *fapitest.Harness, tokens client.TokenSet, resourceID string, want []string) {
	t.Helper()
	v, err := h.NewResourceVerifier(serverresource.Options{Resource: resourceID})
	if err != nil {
		t.Fatalf("NewResourceVerifier(%s): %v", resourceID, err)
	}
	authz := verifyAt(t, h, v, tokens)
	if !slices.Equal(authz.Audience, want) {
		t.Errorf("resource server %s: Audience = %q, want %q", resourceID, authz.Audience, want)
	}
}

// refuseAtResource checks the resource server built with opts refuses
// tokens with invalid_token.
func refuseAtResource(t *testing.T, h *fapitest.Harness, tokens client.TokenSet, opts serverresource.Options) {
	t.Helper()
	v, err := h.NewResourceVerifier(opts)
	if err != nil {
		t.Fatalf("NewResourceVerifier(%+v): %v", opts, err)
	}
	refuseAt(t, h, v, tokens)
}

func verifyAt(t *testing.T, h *fapitest.Harness, v *resource.Verifier, tokens client.TokenSet) resource.AuthorizationContext {
	t.Helper()
	authz, err := v.Verify(context.Background(), resourceRequest(t, h, tokens))
	if err != nil {
		t.Fatalf("resource.Verify: %v", err)
	}
	return authz
}

func refuseAt(t *testing.T, h *fapitest.Harness, v *resource.Verifier, tokens client.TokenSet) {
	t.Helper()
	_, err := v.Verify(context.Background(), resourceRequest(t, h, tokens))
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidToken {
		t.Errorf("resource.Verify = %v, want invalid_token", err)
	}
}

// resourceRequest is a DPoP-bound request presenting tokens' access
// token, with a fresh proof.
func resourceRequest(t *testing.T, h *fapitest.Harness, tokens client.TokenSet) resource.VerifyRequest {
	t.Helper()
	target, err := url.Parse("https://rs.fapitest.internal/data")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := h.NewResourceRequestDPoPProof(context.Background(), "GET", target, tokens.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("NewResourceRequestDPoPProof: %v", err)
	}
	return resource.VerifyRequest{Method: "GET", URL: target, Authorization: "DPoP " + tokens.AccessToken.Reveal(), DPoPProofs: []string{proof}}
}

// wantServerError checks err carries the server's OAuth error code.
func wantServerError(t *testing.T, what string, err error, code string) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("%s = %v, want a *client.Error from the server", what, err)
	}
	if resp, ok := cerr.ServerResponse(); !ok || resp.Code != code {
		t.Errorf("%s server error = %+v (from server %v), want %s", what, resp, ok, code)
	}
}

// TestResourceIndicatorsClientCredentials names resources on a client
// credentials token request, end to end: the access token is issued for
// exactly them and accepted only at their resource servers, and a
// resource the server doesn't serve or the client may not name is
// refused with invalid_target.
func TestResourceIndicatorsClientCredentials(t *testing.T) {
	for _, format := range []struct {
		name   string
		opaque bool
	}{{"JWT", false}, {"opaque", true}} {
		t.Run(format.name, func(t *testing.T) {
			h := fapitest.New(t, fapitest.Config{
				Profile: server.ProfileFAPISecurity, ClientCredentialsGrant: true, OpaqueAccessTokens: format.opaque,
				Resources: servedResources, AllowedResources: []string{payments, accounts, unlisted},
			})
			ctx := context.Background()
			request := func(resources []string) (client.TokenSet, error) {
				result, err := h.Client.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}, Resource: resources})
				return client.TokenSet{AccessToken: result.AccessToken}, err
			}

			t.Run("several resources", func(t *testing.T) {
				tokens, err := request([]string{payments, accounts})
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				if !format.opaque {
					checkJWTAudience(t, tokens, `["`+payments+`","`+accounts+`"]`)
				}
				checkVerifierAudience(t, h, tokens, payments, []string{payments, accounts})
				checkVerifierAudience(t, h, tokens, accounts, []string{payments, accounts})
				refuseAtResource(t, h, tokens, serverresource.Options{Resource: credentials})
				refuseAt(t, h, h.Resource, tokens)
			})

			t.Run("one resource", func(t *testing.T) {
				tokens, err := request([]string{accounts})
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				if !format.opaque {
					checkJWTAudience(t, tokens, `"`+accounts+`"`)
				}
				checkVerifierAudience(t, h, tokens, accounts, []string{accounts})
				refuseAtResource(t, h, tokens, serverresource.Options{Resource: payments})
			})

			t.Run("no resource", func(t *testing.T) {
				tokens, err := request(nil)
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				verifyAt(t, h, h.Resource, tokens)
				refuseAtResource(t, h, tokens, serverresource.Options{Resource: accounts})
			})

			for _, tc := range []struct {
				name      string
				resources []string
			}{
				{"not served", []string{payments, unlisted}},
				{"not allowed for the client", []string{credentials}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					_, err := request(tc.resources)
					wantServerError(t, "RequestClientCredentialsToken", err, "invalid_target")
				})
			}
		})
	}
}
