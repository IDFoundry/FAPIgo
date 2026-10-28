package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// sessionRecordVersion versions the JSON this package hands a
// storage.SessionStore as NewSession.Record. Adding a field is backward
// compatible — an older decoder ignores it, a newer one reads its zero
// value from an older record — so only a change that isn't would bump
// this.
const sessionRecordVersion = 1

// sessionRecord is everything ExchangeCode and HandleAuthorizationResponse
// later need from one authorization attempt, persisted as the opaque
// NewSession.Record: a store never interprets it, so a new field here
// never needs a store change.
type sessionRecord struct {
	Version int `json:"v"`

	// Nonce is the authorization request's "nonce", checked against the
	// ID token's.
	Nonce string `json:"nonce,omitempty"`

	// PKCEVerifier is the code_verifier ExchangeCode presents.
	PKCEVerifier string `json:"pkce_verifier"`

	// Issuer is the authorization server the response must come from.
	Issuer string `json:"issuer"`

	// ClientID is the Config.ClientID of the Client that began the
	// session: only that Client may complete it, so a callback routed to
	// another Client for the same issuer over a shared SessionStore is
	// refused. A record written before this field existed has none, and
	// is refused the same way: sessions last Limits.SessionLifetime, so
	// at most a flow begun before an upgrade has to start again.
	ClientID string `json:"client_id,omitempty"`

	// RedirectURI is the redirect_uri the request carried, presented
	// again at code exchange.
	RedirectURI string `json:"redirect_uri"`

	// ResponseMode is how the response must arrive — plain parameters
	// or a signed JARM response — so it can't be downgraded.
	ResponseMode string `json:"response_mode"`

	// MaxAgeSeconds is the max_age the request carried, in whole
	// seconds, or nil for none: ExchangeCode checks the ID token's
	// auth_time against it.
	MaxAgeSeconds *int64 `json:"max_age,omitempty"`

	// OpenID records that the request's scope included "openid":
	// ExchangeCode then requires an ID token in the token response (OIDC
	// Core §3.1.3.3). A record written before this field existed reads
	// as false.
	OpenID bool `json:"openid,omitempty"`

	// EssentialACR is the request's essential "acr" values, or nil for
	// none: ExchangeCode requires the ID token's acr to be one of them.
	EssentialACR []string `json:"essential_acr,omitempty"`

	// Resource is the request's resource indicators (RFC 8707), or nil
	// for none: ExchangeCode sends them again on its token request.
	Resource []string `json:"resource,omitempty"`

	// Scope is the request's scope: a token response that omits
	// "scope" was granted exactly it (RFC 6749 §5.1). A record written
	// before this field existed reads as none.
	Scope []string `json:"scope,omitempty"`
}

// maxAge is r's max_age, and whether the request carried one.
func (r sessionRecord) maxAge() (time.Duration, bool) {
	if r.MaxAgeSeconds == nil {
		return 0, false
	}
	return time.Duration(*r.MaxAgeSeconds) * time.Second, true
}

func encodeSessionRecord(r sessionRecord) (json.RawMessage, error) {
	r.Version = sessionRecordVersion
	return json.Marshal(r)
}

// errNoSessionRecord is a session a store returned without the Record
// Create gave it: refused, so a store that doesn't persist it can't
// silently skip the checks the record carries.
var errNoSessionRecord = errors.New("the session store returned no session record: it must persist NewSession.Record and return it from Consume")

func decodeSessionRecord(raw json.RawMessage) (sessionRecord, error) {
	if len(raw) == 0 {
		return sessionRecord{}, errNoSessionRecord
	}
	var r sessionRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return sessionRecord{}, fmt.Errorf("decode session record: %w", err)
	}
	if r.Version != sessionRecordVersion {
		return sessionRecord{}, fmt.Errorf("session record version %d, want %d", r.Version, sessionRecordVersion)
	}
	if r.PKCEVerifier == "" || r.Issuer == "" || r.ResponseMode == "" {
		return sessionRecord{}, errors.New("session record is missing its PKCE verifier, issuer or response mode")
	}
	if r.MaxAgeSeconds != nil && (*r.MaxAgeSeconds < 0 || *r.MaxAgeSeconds > maxSessionMaxAgeSeconds) {
		return sessionRecord{}, fmt.Errorf("session record max_age %d is out of range", *r.MaxAgeSeconds)
	}
	if resourceErr := checkResources(r.Resource); resourceErr != nil {
		return sessionRecord{}, fmt.Errorf("session record resource: %w", resourceErr)
	}
	return r, nil
}

// maxSessionMaxAgeSeconds bounds a recorded max_age so it converts to a
// time.Duration, plus any clock skew, without overflowing — the same 100
// years the server package caps max_age at.
const maxSessionMaxAgeSeconds = 100 * 366 * 24 * 60 * 60
