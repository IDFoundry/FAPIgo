package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// tokenSetSealVersion prefixes every sealed TokenSet, so a later format
// can be told apart.
const tokenSetSealVersion byte = 1

// SealTokenSet encrypts t, its tokens and validated ID token claims
// included, for storage — a client that refreshes in the background,
// after a restart or on another instance, needs it back. It uses
// AES-256-GCM under key (32 random bytes the application keeps
// secret), bound to this client's issuer and client ID, so a set sealed
// for another issuer or client doesn't open here. TokenSet itself never
// serializes: fapi.Secret refuses to, so tokens can't reach a log
// through encoding/json by accident.
//
// The result still holds the means to use the tokens once opened: keep
// key and the sealed bytes apart, and rotate key with OpenTokenSet's key
// ring.
func (c *Client) SealTokenSet(t TokenSet, key []byte) ([]byte, error) {
	aead, id, err := tokenSetAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(sealedTokenSetOf(t)) //nolint:gosec // G117: the tokens are what is sealed; this plaintext is encrypted below and never leaves
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{tokenSetSealVersion}, id[:]...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, c.tokenSetAdditionalData()), nil
}

// OpenTokenSet decrypts a TokenSet SealTokenSet sealed, trying each of
// keys: put a new key first in SealTokenSet and keep the old one here
// until every set sealed with it has been re-sealed. It fails for a set
// sealed for another issuer or client, or one that was tampered with. The
// ID token claims come back as they were validated: the ID token itself
// isn't validated again, since it has probably expired.
func (c *Client) OpenTokenSet(sealed []byte, keys ...[]byte) (TokenSet, error) {
	if len(sealed) < 5 || sealed[0] != tokenSetSealVersion {
		return TokenSet{}, errUnreadableTokenSet
	}
	id, rest := [4]byte(sealed[1:5]), sealed[5:]
	for _, key := range keys {
		aead, keyID, err := tokenSetAEAD(key)
		if err != nil {
			return TokenSet{}, err
		}
		if keyID != id || len(rest) < aead.NonceSize() {
			continue
		}
		plaintext, err := aead.Open(nil, rest[:aead.NonceSize()], rest[aead.NonceSize():], c.tokenSetAdditionalData())
		if err != nil {
			return TokenSet{}, errUnreadableTokenSet
		}
		var s sealedTokenSet
		if err := json.Unmarshal(plaintext, &s); err != nil {
			return TokenSet{}, errUnreadableTokenSet
		}
		return s.tokenSet(), nil
	}
	return TokenSet{}, errUnreadableTokenSet
}

var errUnreadableTokenSet = newError(ErrorInvalidRequest, "the sealed token set doesn't open with any key, was sealed for another issuer or client, or was tampered with", nil)

func tokenSetAEAD(key []byte) (cipher.AEAD, [4]byte, error) {
	if len(key) != 32 {
		return nil, [4]byte{}, fmt.Errorf("client: a token set key is %d bytes, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, [4]byte{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, [4]byte{}, err
	}
	sum := sha256.Sum256(key)
	return aead, [4]byte(sum[:4]), nil
}

// tokenSetAdditionalData binds a sealed set to this client's issuer and
// client ID, and the format.
func (c *Client) tokenSetAdditionalData() []byte {
	ad := append([]byte("fapigo token set"), 0, tokenSetSealVersion)
	ad = append(append(ad, c.cfg.Issuer.String()...), 0)
	return append(ad, c.cfg.ClientID.String()...)
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
