package keys

import (
	"context"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// LocalIssuerKeys is an IssuerKeySource for a verifier running in the
// same process as the authorization server it verifies — a resource
// server hosted alongside its AS (a Credential Issuer's Credential
// Endpoint, say), or a test wiring client and server together. It
// resolves keys straight from the KeyManager the authorization server
// signs with, instead of fetching that server's own JWKS over HTTP.
//
// It answers the way the authorization server's published JWKS would:
// with every key the KeyManager reports as currently valid for the
// requested purpose and algorithm — all of them during a
// RotatingKeyManager's overlap window, so a token signed just before a
// rotation still verifies — filtered by KeyID when one is requested. A
// KeyID that matches nothing yields an empty set, like
// JWKSIssuerKeySource. A request for any issuer other than its own is
// an error: it answers for one issuer only.
//
// It performs no network fetch, so it declares LiveFetchHardened; that
// says nothing about the KeyManager itself, whose own suitability for
// production (keys/ephemeral is not) is a separate choice.
type LocalIssuerKeys struct {
	issuer  string
	manager KeyManager
}

// NewLocalIssuerKeys returns a LocalIssuerKeys for issuer, resolving
// keys from manager — the same KeyManager passed to the authorization
// server as Dependencies.Keys (or used by its access-token issuer).
func NewLocalIssuerKeys(issuer fapi.URL, manager KeyManager) (*LocalIssuerKeys, error) {
	if issuer.IsZero() {
		return nil, fmt.Errorf("keys: NewLocalIssuerKeys: issuer is required")
	}
	if manager == nil {
		return nil, fmt.Errorf("keys: NewLocalIssuerKeys: manager is required")
	}
	return &LocalIssuerKeys{issuer: issuer.String(), manager: manager}, nil
}

// ResolveIssuerKeys implements IssuerKeySource.
func (l *LocalIssuerKeys) ResolveIssuerKeys(ctx context.Context, req IssuerKeyRequest) (IssuerKeySet, error) {
	if req.Issuer != l.issuer {
		return IssuerKeySet{}, fmt.Errorf("keys: LocalIssuerKeys for %q cannot resolve keys for issuer %q", l.issuer, req.Issuer)
	}
	purpose, err := signingPurposeFor(req.Purpose)
	if err != nil {
		return IssuerKeySet{}, err
	}
	infos, err := resolveSigningKeys(ctx, SigningKeyUse{Manager: l.manager, Purpose: purpose, Algorithm: req.Algorithm})
	if err != nil {
		return IssuerKeySet{}, err
	}
	var set IssuerKeySet
	for _, info := range infos {
		if req.KeyID != "" && info.KeyID != req.KeyID {
			continue
		}
		set.Keys = append(set.Keys, IssuerKey{KeyID: info.KeyID, Algorithm: req.Algorithm, PublicKey: info.PublicKey})
	}
	return set, nil
}

// Capabilities implements KeySourceAssurance: LocalIssuerKeys never
// fetches over the network.
func (l *LocalIssuerKeys) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}

// signingPurposeFor maps what a verifier checks to the purpose the
// issuer signed it under.
func signingPurposeFor(p IssuerVerificationPurpose) (SigningPurpose, error) {
	switch p {
	case AccessTokenVerification:
		return AccessTokenSigning, nil
	case JARMVerification:
		return JARMSigning, nil
	case IDTokenVerification:
		return IDTokenSigning, nil
	case UserInfoVerification:
		return UserInfoSigning, nil
	default:
		return 0, fmt.Errorf("keys: LocalIssuerKeys: unsupported verification purpose %v", p)
	}
}
