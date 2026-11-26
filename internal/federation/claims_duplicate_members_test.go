package federation

import (
	"errors"
	"strings"
	"testing"
)

// TestParseFederationJWTClaimsRefuseDuplicateMembers: an Entity
// Statement already refuses a repeated member (verify.go); the other
// federation JWTs (Trust Marks, Trust Mark Delegations, Trust Mark
// Status, Resolve and Historical Keys responses) do too. RFC 7519 §4
// requires unique claim names, and encoding/json keeps the last copy of
// a repeated one where another reader of the same JWT may keep the
// first, so the two would see, say, different statuses or subjects.
func TestParseFederationJWTClaimsRefuseDuplicateMembers(t *testing.T) {
	const tm = `"iss":"https://ta.example","sub":"https://rp.example","trust_mark_type":"https://ta.example/tm","iat":1`
	const status = `"iss":"https://ta.example","trust_mark":"x.y.z","iat":1`
	const resolve = `"iss":"https://ta.example","iat":1,"exp":2,"metadata":{"openid_relying_party":{}},"trust_chain":["a.b.c"]`
	const historical = `"iss":"https://ta.example","iat":1,"keys":[]`
	for name, tc := range map[string]struct {
		parse   func([]byte) error
		payload string
		wantErr bool
	}{
		"trust mark":             {parseTM, `{` + tm + `}`, false},
		"trust mark, sub twice":  {parseTM, `{"sub":"https://other.example",` + tm + `}`, true},
		"delegation":             {parseTMD, `{` + tm + `}`, false},
		"delegation, sub twice":  {parseTMD, `{"sub":"https://other.example",` + tm + `}`, true},
		"status":                 {parseTMS, `{` + status + `,"status":"active"}`, false},
		"status twice":           {parseTMS, `{"status":"revoked",` + status + `,"status":"active"}`, true},
		"resolve":                {parseRR, `{"sub":"https://rp.example",` + resolve + `}`, false},
		"resolve, sub twice":     {parseRR, `{"sub":"https://other.example",` + resolve + `,"sub":"https://rp.example"}`, true},
		"resolve, nested repeat": {parseRR, `{"sub":"https://rp.example",` + resolve + `,"x":{"a":1,"a":2}}`, true},
		"historical keys":        {parseHK, `{` + historical + `}`, false},
		"historical keys twice":  {parseHK, `{` + historical + `,"keys":[]}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.parse([]byte(tc.payload))
			switch {
			case !tc.wantErr && err != nil:
				t.Fatalf("parse = %v, want nil", err)
			case tc.wantErr && (!errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name")):
				t.Fatalf("parse = %v, want ErrMalformedClaims for a duplicate member", err)
			}
		})
	}
}

func parseTM(p []byte) error  { _, err := parseTrustMarkClaims(p); return err }
func parseTMD(p []byte) error { _, err := parseTrustMarkDelegationClaims(p); return err }
func parseTMS(p []byte) error { _, err := parseTrustMarkStatusResponseClaims(p); return err }
func parseRR(p []byte) error  { _, err := parseResolveResponseClaims(p); return err }
func parseHK(p []byte) error  { _, err := parseHistoricalKeysClaims(p); return err }
