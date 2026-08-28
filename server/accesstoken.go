package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AccessTokenParams is the input to AccessTokenIssuer.IssueAccessToken.
type AccessTokenParams struct {
	ClientID   fapi.ClientID
	Subject    string
	Scope      []string
	Thumbprint string

	// SenderConstrain says which mechanism Thumbprint represents — a
	// DPoP proof key thumbprint (SenderConstrainDPoP, the zero value)
	// or an mTLS client certificate thumbprint (SenderConstrainMTLS).
	// Always the issuing client's own storage.RegisteredClient.SenderConstrain().
	SenderConstrain storage.SenderConstrain

	Claims map[string]json.RawMessage

	// Issuer and Audience are only meaningful to a self-contained
	// format (JWTAccessTokens uses them as the iss/aud claims) — an
	// opaque token has no self-contained claims, so OpaqueAccessTokens
	// ignores both.
	Issuer   string
	Audience string

	Now      time.Time
	Lifetime time.Duration
	Random   io.Reader
}

// AccessTokenIssuer lets this server mint an access token. Required,
// like every Dependencies field — JWTAccessTokens is the default,
// exported, ship-in-the-box implementation; pass it, or
// OpaqueAccessTokens, or your own.
type AccessTokenIssuer interface {
	// IssueAccessToken returns the raw token plus a revocation-lookup
	// key (a JWT's jti claim for JWTAccessTokens, an opaque token's
	// own hash for OpaqueAccessTokens) — passed to
	// Dependencies.Revocation exactly as returned; its shape is an
	// implementation detail specific to each AccessTokenIssuer.
	IssueAccessToken(ctx context.Context, p AccessTokenParams) (accessToken string, key string, err error)
}

// JWTAccessTokens issues self-contained JWT access tokens (RFC 9068)
// — the format this server has always used, still the default. Owns
// its own signing key and algorithm, independent of Dependencies.Keys
// (still used for ID token/JARM signing).
type JWTAccessTokens struct {
	Keys      keys.KeyManager
	Algorithm fapi.SignatureAlgorithm
}

// NewJWTAccessTokens validates keys/algorithm and returns a
// JWTAccessTokens. Not required — a caller confident its values are
// already correct may use the JWTAccessTokens{...} literal directly —
// but mirrors storage.NewRegisteredClient/ephemeral.NewKeyManager's
// validate-at-construction pattern for callers who want it, since New
// itself only nil-checks Dependencies.AccessTokens (an interface
// value), the same shallow check every other Dependencies field gets.
func NewJWTAccessTokens(keys keys.KeyManager, algorithm fapi.SignatureAlgorithm) (JWTAccessTokens, error) {
	if keys == nil {
		return JWTAccessTokens{}, fmt.Errorf("server: JWTAccessTokens: keys is required")
	}
	if !algorithm.IsValid() {
		return JWTAccessTokens{}, fmt.Errorf("server: JWTAccessTokens: algorithm is invalid")
	}
	return JWTAccessTokens{Keys: keys, Algorithm: algorithm}, nil
}

// IssueAccessToken implements AccessTokenIssuer.
func (j JWTAccessTokens) IssueAccessToken(ctx context.Context, p AccessTokenParams) (string, string, error) {
	signer, kid, err := newSignerFromKeys(ctx, j.Keys, keys.AccessTokenSigning, j.Algorithm)
	if err != nil {
		return "", "", err
	}
	return token.IssueAccessToken(token.AccessTokenParams{
		Signer: signer, Algorithm: j.Algorithm, KeyID: kid,
		Issuer: p.Issuer, Subject: p.Subject, Audience: p.Audience,
		ClientID:     p.ClientID.String(),
		Scope:        strings.Join(p.Scope, " "),
		Confirmation: confirmationFor(p.SenderConstrain, p.Thumbprint),
		Now:          p.Now, Lifetime: p.Lifetime,
		Random:     p.Random,
		Parameters: p.Claims,
	})
}

// confirmationFor builds the "cnf" claim for thumbprint under
// senderConstrain — the one place a bare thumbprint string is turned
// into the correctly-shaped RFC 7800 confirmation (JKT vs X5TS256);
// see internal/token.Confirmation's own doc comment for why exactly
// one is ever set.
func confirmationFor(senderConstrain storage.SenderConstrain, thumbprint string) *token.Confirmation {
	if senderConstrain == storage.SenderConstrainMTLS {
		return &token.Confirmation{X5TS256: thumbprint}
	}
	return &token.Confirmation{JKT: thumbprint}
}

// OpaqueAccessTokens issues opaque, storage-backed access tokens: a
// random value with nothing embedded in it, backed by Store for later
// lookup — the same shape refresh tokens already use (see
// issueRefreshToken), just for access tokens too.
type OpaqueAccessTokens struct {
	Store storage.AccessTokenStore
}

// NewOpaqueAccessTokens validates store is non-nil and returns an
// OpaqueAccessTokens — same validate-at-construction rationale as
// NewJWTAccessTokens.
func NewOpaqueAccessTokens(store storage.AccessTokenStore) (OpaqueAccessTokens, error) {
	if store == nil {
		return OpaqueAccessTokens{}, fmt.Errorf("server: OpaqueAccessTokens: store is required")
	}
	return OpaqueAccessTokens{Store: store}, nil
}

// IssueAccessToken implements AccessTokenIssuer.
func (o OpaqueAccessTokens) IssueAccessToken(ctx context.Context, p AccessTokenParams) (string, string, error) {
	raw, err := generateOpaqueAccessToken(p.Random)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(raw))
	if err := o.Store.CreateAccessToken(ctx, storage.NewAccessToken{
		TokenHash:       hash,
		ClientID:        p.ClientID,
		Subject:         p.Subject,
		Scope:           p.Scope,
		Thumbprint:      p.Thumbprint,
		SenderConstrain: p.SenderConstrain,
		Claims:          p.Claims,
		ExpiresAt:       p.Now.Add(p.Lifetime),
	}); err != nil {
		return "", "", err
	}
	return raw, hex.EncodeToString(hash[:]), nil
}
