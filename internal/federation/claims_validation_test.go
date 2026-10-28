package federation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestParseRefusesStatementsSection32Rejects covers OpenID Federation
// 1.0 §3.2's closing "If any of these validation steps fail, the Entity
// Statement MUST be rejected" for each syntactic rule Parse enforces
// beyond claim placement. iss is https://a.example.org throughout, so a
// sub of https://a.example.org is an Entity Configuration and
// https://b.example.org a Subordinate Statement.
func TestParseRefusesStatementsSection32Rejects(t *testing.T) {
	const ec, ss = "https://a.example.org", "https://b.example.org"
	key := generateKey(t)
	for name, tc := range map[string]struct {
		sub, extra string
		wantErr    bool
	}{
		"§3.2 aud":          {ec, `"aud":"https://op.example.org"`, true},
		"§3.2 trust_anchor": {ec, `"trust_anchor":"https://ta.example.org"`, true},
		"§3.2 trust_anchor_hints in a Subordinate":     {ss, `"trust_anchor_hints":["https://ta.example.org"]`, true},
		"§3.1.2 trust_anchor_hints empty":              {ec, `"trust_anchor_hints":[]`, true},
		"§3.1.2 trust_anchor_hints not an Entity ID":   {ec, `"trust_anchor_hints":["ta.example.org"]`, true},
		"§3.1.2 trust_anchor_hints in an EC":           {ec, `"trust_anchor_hints":["https://ta.example.org"]`, false},
		"§3.1.2 authority_hints empty":                 {ec, `"authority_hints":[]`, true},
		"§3.1.2 authority_hints not an Entity ID":      {ec, `"authority_hints":["not a url"]`, true},
		"§3.1.3 metadata_policy_crit empty":            {ss, `"metadata_policy_crit":[]`, true},
		"§3.1.3 metadata_policy_crit listed":           {ss, `"metadata_policy_crit":["regexp"]`, false},
		"§5 null entity-type metadata":                 {ec, `"metadata":{"openid_relying_party":null}`, true},
		"§5 non-object entity-type metadata":           {ec, `"metadata":{"openid_relying_party":[]}`, true},
		"§5 null metadata parameter":                   {ec, `"metadata":{"openid_relying_party":{"client_name":null}}`, true},
		"§5 null metadata":                             {ec, `"metadata":null`, true},
		"§5 empty entity-type metadata":                {ec, `"metadata":{"openid_relying_party":{}}`, false},
		"§3.2 source_endpoint not a URL":               {ss, `"source_endpoint":"not a url"`, true},
		"§3.2 source_endpoint not https":               {ss, `"source_endpoint":"http://a.example.org/fetch"`, true},
		"§3.2 source_endpoint https":                   {ss, `"source_endpoint":"https://a.example.org/fetch"`, false},
		"§6.1.2 duplicate metadata_policy parameter":   {ss, `"metadata_policy":{"openid_relying_party":{"scope":{"value":"a"},"scope":{"value":"b"}}}`, true},
		"§6.1.2 duplicate metadata_policy operator":    {ss, `"metadata_policy":{"openid_relying_party":{"scope":{"value":"a","value":"b"}}}`, true},
		"§6.1.2 duplicate metadata_policy entity type": {ss, `"metadata_policy":{"openid_relying_party":{},"openid_relying_party":{}}`, true},
		"RFC 7519 §4 duplicate claim":                  {ec, `"iss":"https://a.example.org"`, true},
		"duplicate member inside an array":             {ec, `"metadata":{"openid_relying_party":{"contacts":[{"a":1,"a":2}]}}`, true},
	} {
		payload := fmt.Sprintf(`{"iss":"https://a.example.org","sub":%q,"iat":%d,"exp":%d,"jwks":%s,%s}`, tc.sub, time.Now().Unix(), time.Now().Unix()+60, string(testJWKS(t, key)), tc.extra)
		_, err := Parse(signTestStatement(t, key, `{"alg":"ES256","typ":"entity-statement+jwt","kid":"test-kid"}`, payload))
		if errors.Is(err, ErrMalformedClaims) != tc.wantErr {
			t.Errorf("%s: Parse = %v, want ErrMalformedClaims %v", name, err, tc.wantErr)
		}
	}
}

// TestParseRefusesTrustChainHeaders covers §4.3 and §4.4: "Entity
// Configurations and Subordinate Statements MUST NOT contain the
// trust_chain header parameter", nor peer_trust_chain.
func TestParseRefusesTrustChainHeaders(t *testing.T) {
	key := generateKey(t)
	payload := fmt.Sprintf(`{"iss":"https://a.example.org","sub":"https://a.example.org","iat":%d,"exp":%d,"jwks":%s}`, time.Now().Unix(), time.Now().Unix()+60, string(testJWKS(t, key)))
	for _, name := range []string{"trust_chain", "peer_trust_chain"} {
		header := `{"alg":"ES256","typ":"entity-statement+jwt","kid":"test-kid","` + name + `":["x"]}`
		if _, err := Parse(signTestStatement(t, key, header, payload)); !errors.Is(err, ErrForbiddenHeader) {
			t.Errorf("Parse with a %s header = %v, want ErrForbiddenHeader", name, err)
		}
	}
	if _, err := Parse(signTestStatement(t, key, `{"alg":"ES256","typ":"entity-statement+jwt","kid":"test-kid"}`, payload)); err != nil {
		t.Errorf("Parse without the headers = %v, want nil", err)
	}
}

// signTestStatement signs payload under the literal header JSON, which
// jose.Sign can't produce when it carries a member Header doesn't model.
func signTestStatement(t *testing.T, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
