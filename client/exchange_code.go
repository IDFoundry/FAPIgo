package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/internal/clientassertion"
	"github.com/osanderson/go-fapi/internal/dpop"
	"github.com/osanderson/go-fapi/internal/par"
	"github.com/osanderson/go-fapi/internal/token"
	"github.com/osanderson/go-fapi/keys"
)

// TokenSet is returned by a successful ExchangeCode.
type TokenSet struct {
	AccessToken fapi.Secret
	TokenType   string // always "DPoP"
	ExpiresIn   time.Duration
	Scope       string

	// IDToken and Subject are set only when the granted scope included
	// "openid". Subject comes from the validated ID token, never from an
	// unverified claim.
	IDToken    fapi.Secret
	HasIDToken bool
	Subject    string

	// RefreshToken is set only when the authorization server issued one.
	RefreshToken    fapi.Secret
	HasRefreshToken bool
}

// ExchangeCode authenticates to the token endpoint, presents a DPoP
// proof bound to this request, and redeems resp's authorization code for
// an access token — validating any returned ID token before trusting its
// subject claim.
func (c *Client) ExchangeCode(ctx context.Context, resp ValidatedAuthorizationResponse) (TokenSet, error) {
	now := c.deps.Clock.Now()

	assertionSigner, assertionKID, err := c.newSigner(ctx, keys.ClientAuthentication, c.cfg.Algorithms.ClientAuthentication)
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to resolve client authentication key", err)
	}
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: assertionSigner, Algorithm: c.cfg.Algorithms.ClientAuthentication, KeyID: assertionKID,
		ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
		Now: now, Lifetime: c.cfg.Limits.ClientAssertionLifetime, Random: c.deps.Random,
	})
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to build client assertion", err)
	}

	dpopSigner, _, err := c.newSigner(ctx, keys.DPoPProofSigning, c.cfg.Algorithms.DPoP)
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to resolve DPoP signing key", err)
	}
	tokenURL := c.cfg.Endpoints.Token.URL()
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopSigner, Algorithm: c.cfg.Algorithms.DPoP,
		Method: http.MethodPost, URL: &tokenURL, Now: now, Random: c.deps.Random,
	})
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "failed to build DPoP proof", err)
	}

	form := par.EncodeForm(map[string]string{
		"grant_type":            "authorization_code",
		"code":                  resp.code,
		"redirect_uri":          resp.redirectURI,
		"code_verifier":         resp.pkceVerifier,
		"client_assertion":      assertion,
		"client_assertion_type": clientassertion.AssertionType,
	})

	body, status, err := c.postForm(ctx, c.cfg.Endpoints.Token.String(), form, map[string]string{"DPoP": proof})
	if err != nil {
		return TokenSet{}, newError(ErrorInternal, "token request failed", err)
	}
	if status != http.StatusOK {
		return TokenSet{}, parErrorFromResponse(body)
	}

	raw, err := decodeTokenResponse(body)
	if err != nil {
		return TokenSet{}, newError(ErrorInvalidResponse, "malformed token response", err)
	}
	if raw.TokenType != "DPoP" {
		return TokenSet{}, newError(ErrorInvalidResponse, "token response token_type is not DPoP", nil)
	}

	result := TokenSet{
		AccessToken: fapi.NewSecret(raw.AccessToken),
		TokenType:   raw.TokenType,
		ExpiresIn:   time.Duration(raw.ExpiresIn) * time.Second,
		Scope:       raw.Scope,
	}

	if raw.IDToken != "" {
		subject, idErr := c.validateIDToken(ctx, raw.IDToken, resp.nonce)
		if idErr != nil {
			return TokenSet{}, idErr
		}
		result.IDToken = fapi.NewSecret(raw.IDToken)
		result.HasIDToken = true
		result.Subject = subject
	}
	if raw.RefreshToken != "" {
		result.RefreshToken = fapi.NewSecret(raw.RefreshToken)
		result.HasRefreshToken = true
	}

	return result, nil
}

func (c *Client) validateIDToken(ctx context.Context, raw, nonce string) (string, *Error) {
	parsed, err := token.ParseIDToken(raw)
	if err != nil {
		return "", newError(ErrorInvalidResponse, "malformed ID token", err)
	}

	candidates, err := c.deps.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer: c.cfg.Issuer.String(), Purpose: keys.IDTokenVerification,
		Algorithm: c.cfg.Algorithms.IDToken, KeyID: parsed.KeyID(),
	})
	if err != nil {
		return "", newError(ErrorInternal, "failed to resolve issuer keys", err)
	}
	if len(candidates.Keys) == 0 {
		return "", newError(ErrorInvalidResponse, "no matching issuer key for ID token", nil)
	}

	var (
		validated token.ValidatedIDToken
		verifyErr error
	)
	for _, candidate := range candidates.Keys {
		validated, verifyErr = parsed.Validate(candidate.PublicKey, token.IDTokenValidatePolicy{
			ExpectedIssuer: c.cfg.Issuer.String(), ExpectedAudience: c.cfg.ClientID.String(),
			Algorithm: c.cfg.Algorithms.IDToken, ExpectedNonce: nonce,
			Now: c.deps.Clock.Now(), MaxLifetime: c.cfg.Limits.MaxIDTokenLifetime, MaxClockSkew: c.cfg.Limits.MaxClockSkew,
		})
		if verifyErr == nil {
			break
		}
	}
	if verifyErr != nil {
		return "", newError(ErrorInvalidResponse, "ID token verification failed", verifyErr)
	}
	return validated.Subject, nil
}

type rawTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func decodeTokenResponse(body []byte) (rawTokenResponse, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var raw rawTokenResponse
	if err := dec.Decode(&raw); err != nil {
		return rawTokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	if raw.AccessToken == "" {
		return rawTokenResponse{}, fmt.Errorf("access_token is missing")
	}
	if raw.TokenType == "" {
		return rawTokenResponse{}, fmt.Errorf("token_type is missing")
	}
	if raw.ExpiresIn <= 0 {
		return rawTokenResponse{}, fmt.Errorf("expires_in must be positive")
	}
	return raw, nil
}
