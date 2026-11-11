package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/idfoundry/fapigo/client"
)

// run is what every leg gets: the run's configuration, its own client
// registration, and the CIBA ping notifications the driver's endpoint
// received.
type run struct {
	cfg           runConfig
	leg           legConfig
	notifications <-chan client.BackchannelNotification
}

// codeDPoP is leg 1: authorization code + PAR + PKCE + private_key_jwt
// + DPoP-bound tokens; the ID token, UserInfo, and a refresh.
func codeDPoP(ctx context.Context, r run) error {
	return codeFlow(ctx, r, clientShape{profile: client.ProfileFAPISecurity}, "DPoP")
}

// codeMTLS is leg 2: authorization code + PAR + PKCE with
// mutual-TLS client authentication (self_signed_tls_client_auth, or
// tls_client_auth where the leg says so) and certificate-bound tokens,
// through the server's mtls_endpoint_aliases.
func codeMTLS(ctx context.Context, r run) error {
	return codeFlow(ctx, r, clientShape{profile: client.ProfileFAPISecurity, authMTLS: true, senderMTLS: true}, "Bearer")
}

// messageSigning is leg 3: a signed request object (JAR) pushed via
// PAR, a JARM response, private_key_jwt + DPoP.
func messageSigning(ctx context.Context, r run) error {
	return codeFlow(ctx, r, clientShape{profile: client.ProfileFAPISecurityWithMessageSigning}, "DPoP")
}

func codeFlow(ctx context.Context, r run, shape clientShape, wantTokenType string) error {
	cl, err := newClient(ctx, r.cfg, r.leg, shape)
	if err != nil {
		return err
	}
	browser, err := newUserAgent(r.cfg)
	if err != nil {
		return err
	}

	session, err := cl.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: r.leg.Scope, Resource: r.leg.Resource})
	if err != nil {
		return fmt.Errorf("begin authorization: %w", err)
	}
	rawQuery, err := browser.authorize(session.URL().String(), r.leg.RedirectURI)
	if err != nil {
		return fmt.Errorf("user agent: %w", err)
	}
	completion, err := cl.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: session.Handle()})
	if err != nil {
		return fmt.Errorf("complete authorization: %w", err)
	}
	success, ok := completion.(client.CompletionSuccess)
	if !ok {
		return fmt.Errorf("authorization was not granted: %+v", completion)
	}
	tokens := success.Tokens
	if err := checkTokens(r, tokens, wantTokenType); err != nil {
		return err
	}
	if err := checkUserInfo(ctx, r, cl, tokens); err != nil {
		return err
	}

	if !tokens.HasRefreshToken {
		return errors.New("token response carried no refresh token")
	}
	refreshed, err := cl.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens})
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}
	if refreshed.AccessToken.Reveal() == tokens.AccessToken.Reveal() {
		return errors.New("refresh returned the same access token")
	}
	if err := checkTokens(r, refreshed, wantTokenType); err != nil {
		return fmt.Errorf("refreshed tokens: %w", err)
	}
	if err := checkUserInfo(ctx, r, cl, refreshed); err != nil {
		return fmt.Errorf("refreshed tokens: %w", err)
	}
	return nil
}

// clientCredentials is leg 4: client_credentials + private_key_jwt +
// DPoP, with a resource indicator (RFC 8707) where the leg names one.
func clientCredentials(ctx context.Context, r run) error {
	cl, err := newClient(ctx, r.cfg, r.leg, clientShape{profile: client.ProfileFAPISecurity})
	if err != nil {
		return err
	}
	result, err := cl.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: r.leg.Scope, Resource: r.leg.Resource})
	if err != nil {
		return fmt.Errorf("client_credentials: %w", err)
	}
	if result.AccessToken.Reveal() == "" {
		return errors.New("no access token")
	}
	if result.TokenType != "DPoP" {
		return fmt.Errorf("token_type %q, want DPoP", result.TokenType)
	}
	if got := strings.Fields(result.Scope); !slices.Equal(got, r.leg.Scope) {
		return fmt.Errorf("granted scope %q, want %q", result.Scope, strings.Join(r.leg.Scope, " "))
	}
	return nil
}

func checkTokens(r run, tokens client.TokenSet, wantTokenType string) error {
	if tokens.AccessToken.Reveal() == "" {
		return errors.New("no access token")
	}
	if tokens.TokenType != wantTokenType {
		return fmt.Errorf("token_type %q, want %s", tokens.TokenType, wantTokenType)
	}
	if !tokens.HasIDToken {
		return errors.New("no ID token")
	}
	if tokens.Subject != r.cfg.Subject {
		return fmt.Errorf("ID token sub %q, want %q", tokens.Subject, r.cfg.Subject)
	}
	return nil
}

// checkUserInfo calls the UserInfo endpoint with tokens' access token,
// sender-constrained as the client is configured; FetchUserInfo checks
// the response's sub against the ID token's.
func checkUserInfo(ctx context.Context, r run, cl *client.Client, tokens client.TokenSet) error {
	info, err := cl.FetchUserInfo(ctx, tokens)
	if err != nil {
		return fmt.Errorf("userinfo: %w", err)
	}
	if info.Subject != r.cfg.Subject {
		return fmt.Errorf("userinfo sub %q, want %q", info.Subject, r.cfg.Subject)
	}
	return nil
}
