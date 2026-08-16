package dpop

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/osanderson/go-fapi/internal/canonical"
	"github.com/osanderson/go-fapi/internal/jose"
)

// ReplayChecker records that a DPoP proof's "jti" has been used, failing
// if it has been seen before. Implementations are expected to key
// storage by a namespaced digest of jti, not the raw value — see
// storage.ReplayStore — but that adaptation is the caller's
// responsibility so this package stays decoupled from a specific storage
// contract.
type ReplayChecker interface {
	UseOnce(ctx context.Context, jti string, expiresAt time.Time) error
}

// VerifyRequest describes one DPoP proof to verify.
type VerifyRequest struct {
	// Proof is the compact JWS presented in the DPoP header.
	Proof string

	// Method and URL are the HTTP method and target URI of the request
	// the proof was presented with. The proof's "htm"/"htu" claims must
	// match them exactly (after canonicalization).
	Method string
	URL    *url.URL

	// AccessToken, if non-empty, is the access token presented alongside
	// this proof. When set, the proof's "ath" claim must match its hash;
	// when empty, the proof must not carry an "ath" claim at all.
	AccessToken string

	// RequiredNonce, if non-empty, is the nonce this verifier previously
	// issued; the proof's "nonce" claim must match it exactly.
	RequiredNonce string

	// Now is the time to validate the proof's "iat" against.
	Now time.Time

	// MaxProofAge is how old (relative to Now) a proof's "iat" may be
	// before it is rejected. Required — there is no implicit default.
	MaxProofAge time.Duration

	// MaxClockSkew bounds how far in the future (relative to Now) a
	// proof's "iat" may be before it is rejected. Zero means no
	// tolerance for a future-dated proof.
	MaxClockSkew time.Duration

	// Replay, if non-nil, is used to detect proof replay by "jti". A nil
	// Replay skips replay detection — callers verifying in a context
	// where replay detection happens elsewhere may pass nil, but server
	// and resource verification must always supply one.
	Replay ReplayChecker
}

// VerifiedProof is everything about a DPoP proof worth retaining once it
// has been verified: the thumbprint of the key it was signed with (for
// binding against a token's cnf.jkt) and when it was issued.
type VerifiedProof struct {
	Thumbprint jose.Thumbprint
	IssuedAt   time.Time
}

// Verify checks a DPoP proof against req. On success, the returned
// VerifiedProof's Thumbprint identifies the key that produced it — the
// caller is responsible for checking that thumbprint against whatever it
// expects (e.g. a token's cnf.jkt), since what counts as "expected"
// differs between the authorization server issuing a token and a
// resource server checking one.
func Verify(ctx context.Context, req VerifyRequest) (VerifiedProof, error) {
	if req.Method == "" {
		return VerifiedProof{}, fmt.Errorf("dpop: method is empty")
	}
	if req.URL == nil {
		return VerifiedProof{}, fmt.Errorf("dpop: url is nil")
	}
	if req.Now.IsZero() {
		return VerifiedProof{}, fmt.Errorf("dpop: now is zero")
	}
	if req.MaxProofAge <= 0 {
		return VerifiedProof{}, fmt.Errorf("dpop: MaxProofAge must be positive")
	}

	compact, err := jose.ParseCompact(req.Proof)
	if err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: %w", err)
	}
	if compact.Header.Type != jwtType {
		return VerifiedProof{}, ErrWrongType
	}
	if compact.Header.JWK == nil {
		return VerifiedProof{}, ErrMissingJWK
	}
	if err := compact.Verify(compact.Header.JWK.PublicKey(), compact.Header.Algorithm); err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: %w", err)
	}

	c, err := parseClaims(compact.Payload)
	if err != nil {
		return VerifiedProof{}, err
	}

	if c.HTM != strings.ToUpper(req.Method) {
		return VerifiedProof{}, ErrMethodMismatch
	}
	// htu is compared canonicalized on both sides (RFC 9449 §4.3: "the
	// query and fragment parts of the htu... are ignored"), not as a raw
	// string — a proof's own htu claim may legitimately differ from
	// req.URL in case or in carrying a query/fragment the sender didn't
	// bother to strip.
	htu, err := url.Parse(c.HTU)
	if err != nil {
		return VerifiedProof{}, ErrURIMismatch
	}
	if canonical.URI(htu) != canonical.URI(req.URL) {
		return VerifiedProof{}, ErrURIMismatch
	}

	iat := time.Unix(c.IAT, 0)
	if iat.After(req.Now.Add(req.MaxClockSkew)) {
		return VerifiedProof{}, ErrIssuedInFuture
	}
	if req.Now.Sub(iat) > req.MaxProofAge {
		return VerifiedProof{}, ErrExpired
	}

	if req.AccessToken != "" {
		want := accessTokenHash(req.AccessToken)
		if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(want)) != 1 {
			return VerifiedProof{}, ErrAccessTokenHashMismatch
		}
	} else if c.ATH != "" {
		return VerifiedProof{}, ErrAccessTokenHashMismatch
	}

	if req.RequiredNonce != "" {
		if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(req.RequiredNonce)) != 1 {
			return VerifiedProof{}, ErrNonceMismatch
		}
	}

	if req.Replay != nil {
		if err := req.Replay.UseOnce(ctx, c.JTI, iat.Add(req.MaxProofAge)); err != nil {
			return VerifiedProof{}, fmt.Errorf("dpop: replay check: %w", err)
		}
	}

	thumbprint, err := compact.Header.JWK.Thumbprint()
	if err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: %w", err)
	}
	return VerifiedProof{Thumbprint: thumbprint, IssuedAt: iat}, nil
}
