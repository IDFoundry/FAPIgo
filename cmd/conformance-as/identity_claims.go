package main

import (
	"context"
	"encoding/json"

	"github.com/osanderson/go-fapi/server"
)

// staticIdentityClaims resolves a fixed set of identity claim values for
// this binary's one canned subject — there is no real user store here,
// and conformance modules like
// fapi2-security-profile-final-test-claims-parameter-identity-claims
// require a subject that actually has every claim in claims_supported
// populated, not just proof the plumbing exists. Implements
// server.IdentityClaimsSource.
//
// updated_at is resolved once, at construction, and reused for every
// call — not recomputed per-call from the clock. The ID token and the
// UserInfo response are two independent calls to ResolveIdentityClaims
// (server/token.go's withIdentityClaims for the former,
// userinfoHandler for the latter), and the suite's
// AddIdentityClaimsFromUserInfo condition requires updated_at to match
// exactly between them — a live clock.Now() per call would only agree
// by coincidence.
type staticIdentityClaims struct {
	subject   string
	updatedAt int64
}

func newStaticIdentityClaims(subject string, clock server.Clock) staticIdentityClaims {
	return staticIdentityClaims{subject: subject, updatedAt: clock.Now().Unix()}
}

// identityClaimNames is claims_supported's identity-claim subset (see
// metadata.go) — kept alongside staticIdentityClaims so the two can't
// drift apart silently.
var identityClaimNames = []string{
	"name", "given_name", "family_name", "email", "email_verified",
	"preferred_username", "zoneinfo", "locale", "updated_at",
}

// ResolveIdentityClaims returns values only for the claim names in
// names — a name not in names is never included, even though this
// source has a value for every claim in identityClaimNames. Returning
// everything this source knows about a subject, regardless of what was
// actually requested, would leak claims to a client that never asked
// for them (OIDC Core §5.5 is opt-in disclosure, not a suggestion).
func (s staticIdentityClaims) ResolveIdentityClaims(_ context.Context, subject string, names []string) (map[string]json.RawMessage, error) {
	if subject != s.subject || len(names) == 0 {
		return nil, nil
	}
	values := map[string]any{
		"name":               "Conformance Test User",
		"given_name":         "Conformance",
		"family_name":        "User",
		"email":              "conformance-test-user@example.com",
		"email_verified":     true,
		"preferred_username": "conformance-test-user",
		"zoneinfo":           "Europe/London",
		"locale":             "en-GB",
		"updated_at":         s.updatedAt,
	}
	out := make(map[string]json.RawMessage, len(names))
	for _, name := range names {
		v, ok := values[name]
		if !ok {
			continue
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out[name] = encoded
	}
	return out, nil
}
