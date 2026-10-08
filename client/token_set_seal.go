package client

import (
	"encoding/json"
	"errors"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// tokenSetSealVersion prefixes every sealed TokenSet, so a later format
// can be told apart.
const tokenSetSealVersion byte = 1

// ErrUnreadableTokenSet is the cause, for errors.Is, of a
// TokenSetSealer.Open failure on a set that doesn't open: sealed with no
// key it has, for another issuer, client or owner, or tampered with.
// There is nothing to recover: sign the user in again.
var ErrUnreadableTokenSet = errors.New("client: the sealed token set doesn't open")

// TokenSetSealer encrypts a TokenSet for storage, and opens it again: a
// client that refreshes in the background, after a restart or on
// another instance, needs it back. TokenSet itself never serializes:
// fapi.Secret refuses to, so tokens can't reach a log through
// encoding/json by accident.
//
// A sealed set is AES-256-GCM, bound to this client's issuer and client
// ID and to an owner the caller names (the user, account or connection
// whose tokens they are), so one row can't be swapped into another's:
// it opens only for the owner it was sealed for.
//
// The restored access token is still sender-constrained: to the DPoP key
// or TLS client certificate this client presented for it
// (Dependencies.Keys). Another instance needs the same key, or must
// refresh first.
type TokenSetSealer struct {
	client *Client
	keys   sealKeyring
}

// NewTokenSetSealer returns a TokenSetSealer for c that seals with
// keys[0] and opens with any of keys, each 32 random bytes the
// application keeps secret. Rotate by putting a new key first: Open says
// when a set it opened was sealed with an older key, to seal again and
// store, and the old key goes once nothing sealed with it remains.
func NewTokenSetSealer(c *Client, keys [][]byte) (*TokenSetSealer, error) {
	if c == nil {
		return nil, errors.New("client: NewTokenSetSealer needs a Client")
	}
	ring, err := newSealKeyring("token set", keys)
	if err != nil {
		return nil, err
	}
	return &TokenSetSealer{client: c, keys: ring}, nil
}

// Seal encrypts t, its tokens and validated ID token claims included,
// for owner: whatever names whose tokens these are, such as a user or
// connection ID, and must be given to Open again. owner is required.
// The sealed set is bound to this client's issuer, which Open restores
// as TokenSet.Issuer, so a set from another issuer (by its Issuer, or
// its ID token's iss) is refused rather than relabelled.
func (s *TokenSetSealer) Seal(t TokenSet, owner string) ([]byte, error) {
	if owner == "" {
		return nil, newError(ErrorInvalidRequest, "a token set is sealed for an owner", nil)
	}
	if iss := tokenSetIssuer(t); iss != "" && iss != s.client.cfg.Issuer.String() {
		return nil, newError(ErrorInvalidRequest, "the token set was issued by a different issuer than this client's", nil)
	}
	if t.HasIDToken && t.IDTokenClaims.Issuer != "" && t.IDTokenClaims.Issuer != s.client.cfg.Issuer.String() {
		return nil, newError(ErrorInvalidRequest, "the token set's ID token was issued by a different issuer than this client's", nil)
	}
	plaintext, err := json.Marshal(sealedTokenSetOf(t)) //nolint:gosec // G117: the tokens are what is sealed; this plaintext is encrypted below and never leaves
	if err != nil {
		return nil, newError(ErrorInternal, "failed to encode the token set", err)
	}
	return s.keys.seal(tokenSetSealVersion, plaintext, s.additionalData(owner)), nil
}

// Open decrypts a set Seal sealed for owner. The ID token claims come
// back as they were validated: the ID token itself isn't validated
// again, since it has probably expired. reseal reports a set sealed with
// a key other than the first: seal it again and store the result, so the
// old key can go. Any failure to open is an *Error whose cause is
// ErrUnreadableTokenSet.
func (s *TokenSetSealer) Open(sealed []byte, owner string) (t TokenSet, reseal bool, err error) {
	plaintext, keyIndex, ok := s.keys.open(tokenSetSealVersion, sealed, s.additionalData(owner))
	if !ok {
		return TokenSet{}, false, errUnreadableTokenSet()
	}
	var st sealedTokenSet
	if err := json.Unmarshal(plaintext, &st); err != nil {
		return TokenSet{}, false, errUnreadableTokenSet()
	}
	t = st.tokenSet()
	// The additional data bound the set to this issuer.
	t.Issuer = s.client.cfg.Issuer.String()
	return t, keyIndex > 0, nil
}

func errUnreadableTokenSet() *Error {
	return newError(ErrorInvalidRequest, "the sealed token set doesn't open: sign the user in again", ErrUnreadableTokenSet)
}

// additionalData binds a sealed set to the format, this client's issuer
// and client ID, and owner, each length-prefixed so no two differ only
// in where one ends.
func (s *TokenSetSealer) additionalData(owner string) []byte {
	return sealAdditionalData("fapigo token set", tokenSetSealVersion, s.client.cfg.Issuer.String(), s.client.cfg.ClientID.String(), owner)
}

// sealedTokenSet is the JSON a sealed TokenSet encrypts.
type sealedTokenSet struct {
	AccessToken          string          `json:"access_token"`
	TokenType            string          `json:"token_type"`
	Scope                string          `json:"scope,omitempty"`
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
	ExpiresIn            *time.Duration  `json:"expires_in,omitempty"`
	ObtainedAt           time.Time       `json:"obtained_at"`
	IDToken              *string         `json:"id_token,omitempty"`
	Subject              string          `json:"sub,omitempty"`
	IDTokenClaims        *sealedClaims   `json:"id_token_claims,omitempty"`
	RefreshToken         *string         `json:"refresh_token,omitempty"`
}

type sealedClaims struct {
	Subject    string                     `json:"sub"`
	AuthTime   time.Time                  `json:"auth_time"`
	ACR        string                     `json:"acr,omitempty"`
	AMR        []string                   `json:"amr,omitempty"`
	Parameters map[string]json.RawMessage `json:"parameters,omitempty"`
	ExpiresAt  time.Time                  `json:"exp"`
	IssuedAt   time.Time                  `json:"iat"`
	Issuer     string                     `json:"iss"`
	Audience   []string                   `json:"aud"`
	Nonce      string                     `json:"nonce,omitempty"`
	AZP        string                     `json:"azp,omitempty"`
}

func sealedTokenSetOf(t TokenSet) sealedTokenSet {
	s := sealedTokenSet{
		AccessToken: t.AccessToken.Reveal(), TokenType: t.TokenType, Scope: t.Scope,
		AuthorizationDetails: t.AuthorizationDetails, ObtainedAt: t.ObtainedAt, Subject: t.Subject,
	}
	if t.HasExpiresIn {
		s.ExpiresIn = &t.ExpiresIn
	}
	if t.HasIDToken {
		idToken, c := t.IDToken.Reveal(), t.IDTokenClaims
		s.IDToken = &idToken
		s.IDTokenClaims = &sealedClaims{
			Subject: c.Subject, AuthTime: c.AuthTime, ACR: c.ACR, AMR: c.AMR, Parameters: c.Parameters,
			ExpiresAt: c.ExpiresAt, IssuedAt: c.IssuedAt, Issuer: c.Issuer, Audience: c.Audience, Nonce: c.Nonce, AZP: c.AZP,
		}
	}
	if t.HasRefreshToken {
		refresh := t.RefreshToken.Reveal()
		s.RefreshToken = &refresh
	}
	return s
}

func (s sealedTokenSet) tokenSet() TokenSet {
	t := TokenSet{
		AccessToken: fapi.NewSecret(s.AccessToken), TokenType: s.TokenType, Scope: s.Scope,
		AuthorizationDetails: s.AuthorizationDetails, ObtainedAt: s.ObtainedAt, Subject: s.Subject,
	}
	if s.ExpiresIn != nil {
		t.ExpiresIn, t.HasExpiresIn = *s.ExpiresIn, true
	}
	if s.IDToken != nil {
		t.IDToken, t.HasIDToken = fapi.NewSecret(*s.IDToken), true
		if c := s.IDTokenClaims; c != nil {
			t.IDTokenClaims = IDTokenClaims{
				Subject: c.Subject, AuthTime: c.AuthTime, ACR: c.ACR, AMR: c.AMR, Parameters: c.Parameters,
				ExpiresAt: c.ExpiresAt, IssuedAt: c.IssuedAt, Issuer: c.Issuer, Audience: c.Audience, Nonce: c.Nonce, AZP: c.AZP,
			}
		}
	}
	if s.RefreshToken != nil {
		t.RefreshToken, t.HasRefreshToken = fapi.NewSecret(*s.RefreshToken), true
	}
	return t
}
