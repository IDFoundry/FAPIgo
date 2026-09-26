package server

import (
	"encoding/json"
	"fmt"
	"time"
)

// recordVersion versions the JSON payloads this package hands storage
// implementations as opaque values (the Request and Grant fields on
// storage's record types). Adding a field is backward compatible — an
// older decoder ignores it, a newer one reads its zero value from an
// older record — so only a change that isn't would bump this.
const recordVersion = 1

// requestRecord is what a pushed authorization request or CIBA
// backchannel authentication request persists as its opaque Request:
// everything this package later needs from the original request, none
// of which a store ever interprets.
type requestRecord struct {
	Version int `json:"v"`

	// Parameters are the request's validated parameters.
	Parameters map[string]json.RawMessage `json:"parameters"`

	// TokenClaims are the extension parameter values
	// (extension.Definition.ReturnInTokenClaims) to copy into any token
	// this request eventually produces.
	TokenClaims map[string]json.RawMessage `json:"token_claims,omitempty"`

	// DPoPJKT is the DPoP key thumbprint a CIBA request was bound to at
	// creation. A pushed authorization request carries its binding as
	// the "dpop_jkt" parameter instead.
	DPoPJKT string `json:"dpop_jkt,omitempty"`
}

// grantRecord is what an authorization code, refresh token or approved
// CIBA request persists as its opaque Grant: the complete authorization
// every token issued from it is built from. One type serves all three,
// so a new per-grant field is added here once rather than to each
// storage record type — and never requires a store change.
type grantRecord struct {
	Version int `json:"v"`

	// RedirectURI, CodeChallenge and Nonce apply to an authorization
	// code only (the code exchange checks the first two; the first ID
	// token carries the third) and are cleared for a refresh token.
	RedirectURI   string `json:"redirect_uri,omitempty"`
	CodeChallenge string `json:"code_challenge,omitempty"`
	Nonce         string `json:"nonce,omitempty"`

	// DPoPJKT is the DPoP key thumbprint the authorization request was
	// bound to (RFC 9449 §10), if any.
	DPoPJKT string `json:"dpop_jkt,omitempty"`

	// Thumbprint is the DPoP key thumbprint presented when a refresh
	// token was issued — recorded for reference only; see
	// RefreshAccessToken.
	Thumbprint string `json:"thumbprint,omitempty"`

	Subject              string          `json:"sub"`
	Scope                []string        `json:"scope,omitempty"`
	AuthTime             time.Time       `json:"auth_time"`
	ACR                  string          `json:"acr,omitempty"`
	AMR                  []string        `json:"amr,omitempty"`
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// TokenClaims are the extension claims (ReturnInTokenClaims) for
	// both the access and ID tokens.
	TokenClaims map[string]json.RawMessage `json:"token_claims,omitempty"`

	// RequestedIDTokenClaims and RequestedUserinfoClaims are the claim
	// names the request's "claims" parameter (OIDC Core §5.5) asked
	// for, by delivery location. No identity claim outside these may be
	// issued: an IdentityClaimsSource may hold more than was requested.
	RequestedIDTokenClaims  []string `json:"requested_id_token_claims,omitempty"`
	RequestedUserinfoClaims []string `json:"requested_userinfo_claims,omitempty"`
}

// forRefreshToken returns g as a refresh token carries it forward:
// without the code-exchange-only fields, and recording thumbprint.
func (g grantRecord) forRefreshToken(thumbprint string) grantRecord {
	g.RedirectURI = ""
	g.CodeChallenge = ""
	g.Nonce = ""
	g.Thumbprint = thumbprint
	return g
}

// accessTokenClaims returns the non-standard claims for an access token
// issued from g: its extension claims, the "claims" parameter's
// userinfo-scoped names (see RequestedUserinfoClaimsKey), and its
// granted authorization_details.
func (g grantRecord) accessTokenClaims() (map[string]json.RawMessage, error) {
	claims, err := withRequestedUserinfoClaims(g.RequestedUserinfoClaims, g.TokenClaims)
	if err != nil {
		return nil, err
	}
	return withAuthorizationDetails(g.AuthorizationDetails, claims), nil
}

func encodeRequestRecord(r requestRecord) (json.RawMessage, error) {
	r.Version = recordVersion
	return json.Marshal(r)
}

func decodeRequestRecord(raw json.RawMessage) (requestRecord, error) {
	var r requestRecord
	if err := decodeRecord(raw, &r.Version, &r); err != nil {
		return requestRecord{}, fmt.Errorf("stored request: %w", err)
	}
	return r, nil
}

func encodeGrantRecord(g grantRecord) (json.RawMessage, error) {
	g.Version = recordVersion
	return json.Marshal(g)
}

func decodeGrantRecord(raw json.RawMessage) (grantRecord, error) {
	var g grantRecord
	if err := decodeRecord(raw, &g.Version, &g); err != nil {
		return grantRecord{}, fmt.Errorf("stored grant: %w", err)
	}
	return g, nil
}

// decodeRecord unmarshals raw into dst and checks the version field
// (version points into dst) is one this package can read.
func decodeRecord(raw json.RawMessage, version *int, dst any) error {
	if len(raw) == 0 {
		return fmt.Errorf("record is empty")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("record is malformed: %w", err)
	}
	if *version != recordVersion {
		return fmt.Errorf("record version %d is not supported", *version)
	}
	return nil
}
