package federation

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// relyingPartyMetadataNames is every member name relyingPartyMetadata
// reads.
func relyingPartyMetadataNames() []string {
	t := reflect.TypeOf(relyingPartyMetadata{})
	names := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// FuzzRegisteredClientConfigFromMetadata exercises automatic
// registration's reading of a Relying Party's openid_relying_party
// metadata, which the RP itself publishes. Beyond never panicking:
//
//   - a member naming a known parameter only in a different case is
//     always refused, never read (superiors' metadata policy only ever
//     sees the exact name);
//   - what the operator grants — scopes, client_credentials, CIBA, the
//     allowed authentication methods — never comes from the metadata;
//   - an accepted configuration may still be refused by
//     storage.NewRegisteredClient, which is fail-closed, but must not
//     panic it.
//
// jwks_uri inputs are skipped: fetching is fapihttp's concern, and a
// fuzz run must not make network requests.
func FuzzRegisteredClientConfigFromMetadata(f *testing.F) {
	f.Add(validRPMetadataJSON(), uint8(0))
	f.Add(`{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_methods_supported":["tls_client_auth","private_key_jwt"],"tls_client_auth_subject_dn":"CN=rp","jwks":`+testRPJWKS+`}`, uint8(0b1100))
	f.Add(`{"redirect_uris":["https://rp.example.org/cb"],"Token_Endpoint_Auth_Method":"tls_client_auth","tls_client_auth_subject_dn":"CN=rp","jwks":`+testRPJWKS+`}`, uint8(0))
	f.Add(`{"redirect_uris":["https://rp.example.org/cb"],"token_endpoint_auth_method":"private_key_jwt","jwks":`+testRPJWKS+`,"backchannel_token_delivery_mode":"ping","backchannel_client_notification_endpoint":"https://rp.example.org/n"}`, uint8(0b0101))
	names := relyingPartyMetadataNames()
	const id = fapi.ClientID("https://rp.example.org")

	f.Fuzz(func(t *testing.T, raw string, flags uint8) {
		var members map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &members) != nil {
			return
		}
		if _, ok := members["jwks_uri"]; ok {
			return
		}
		cfg := AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}}
		cfg.AllowsCIBA = flags&1 != 0
		cfg.AllowsClientCredentialsGrant = flags&2 != 0
		if flags&4 != 0 {
			cfg.ClientAssertionAlgorithms = []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256}
		}
		if flags&8 != 0 {
			cfg.AllowedClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT}
		}
		repo := &AutomaticClientRepository{cfg: cfg}

		got, jwks, err := repo.registeredClientConfigFromMetadata(context.Background(), id, json.RawMessage(raw))

		for member := range members {
			for _, name := range names {
				if member != name && strings.EqualFold(member, name) && err == nil {
					t.Fatalf("member %q, a case variant of %q, was accepted", member, name)
				}
			}
		}
		if err != nil {
			return
		}
		if got.ID != id || !got.AutomaticFederationRegistration || len(got.RedirectURIs) == 0 || len(jwks) == 0 {
			t.Fatalf("accepted config %+v (jwks %d bytes) lacks its id, redirect URIs, jwks or federation marker", got, len(jwks))
		}
		if !slices.Equal(got.AllowedScopes, cfg.AllowedScopes) || got.AllowsClientCredentialsGrant != cfg.AllowsClientCredentialsGrant {
			t.Fatalf("scopes %v / client_credentials %v came from somewhere other than the operator's config", got.AllowedScopes, got.AllowsClientCredentialsGrant)
		}
		if !cfg.AllowsCIBA && (got.BackchannelTokenDeliveryMode != 0 || got.BackchannelAuthenticationRequestAlgorithm != 0) {
			t.Fatalf("CIBA configured (%v) although the operator doesn't allow it", got.BackchannelTokenDeliveryMode)
		}
		if len(cfg.AllowedClientAuthMethods) > 0 {
			for _, m := range append(slices.Clone(got.ClientAuthMethods), got.ClientAuthMethod) {
				if m != 0 && !slices.Contains(cfg.AllowedClientAuthMethods, m) {
					t.Fatalf("registered method %v outside AllowedClientAuthMethods", m)
				}
			}
		}
		_, _ = storage.NewRegisteredClient(got) // may refuse; must not panic
	})
}

// FuzzDomainNameConstraintMatches checks naming-constraint matching
// (OpenID Federation 1.0 §6.2.2, RFC 5280 §4.2.1.10 syntax) against a
// plain reference for ASCII names, and for any input that a "."
// constraint never matches the bare domain, and that exclusion always
// wins over permission.
func FuzzDomainNameConstraintMatches(f *testing.F) {
	f.Add(".example.com", "host.example.com")
	f.Add(".example.com", "example.com")
	f.Add("example.com", "EXAMPLE.com")
	f.Add(".com", "a.b.com")
	f.Add(".", "a.")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, constraint, host string) {
		got := domainNameConstraintMatches(constraint, host)

		if isASCII(constraint) && isASCII(host) {
			c, h := strings.ToLower(constraint), strings.ToLower(host)
			want := c == h
			if strings.HasPrefix(c, ".") {
				want = len(h) > len(c) && strings.HasSuffix(h, c)
			}
			if got != want {
				t.Fatalf("domainNameConstraintMatches(%q, %q) = %v, want %v", constraint, host, got, want)
			}
		}
		if strings.HasPrefix(constraint, ".") && domainNameConstraintMatches(constraint, constraint[1:]) {
			t.Fatalf("subtree constraint %q matches its bare domain", constraint)
		}

		entityID := "https://" + host
		if ValidEntityID(entityID) != nil {
			return
		}
		nc := NamingConstraints{Permitted: []string{constraint}, Excluded: []string{constraint}}
		if err := checkNamingConstraint(nc, entityID); got && err == nil {
			t.Fatalf("entity %q both permitted and excluded by %q was accepted", entityID, constraint)
		}
		permitted := checkNamingConstraint(NamingConstraints{Permitted: []string{constraint}}, entityID) == nil
		if u, _ := url.Parse(entityID); permitted != domainNameConstraintMatches(constraint, u.Hostname()) {
			t.Fatalf("checkNamingConstraint(permitted %q, %q) = %v, disagreeing with the host match", constraint, entityID, permitted)
		}
	})
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// FuzzApplySuperiorMetadata exercises applying a superior's metadata to
// its subject (OpenID Federation 1.0 §3.1.1, §6.1.4.2) with arbitrary
// metadata from both. On success, the subject's input is unchanged, the
// result has exactly the subject's Entity Types, each parameter the
// superior sets carries the superior's value, and every other
// parameter keeps the subject's.
func FuzzApplySuperiorMetadata(f *testing.F) {
	f.Add(`{"openid_relying_party":{"client_name":"RP","contacts":["a@rp"]}}`, `{"openid_relying_party":{"contacts":["ops@ta"]},"openid_provider":{"issuer":"x"}}`)
	f.Add(`{"openid_relying_party":null}`, `{"openid_relying_party":{"a":1}}`)
	f.Add(`{"x":{"a":1}}`, `{}`)

	f.Fuzz(func(t *testing.T, subjectJSON, superiorJSON string) {
		var subject, superior map[string]json.RawMessage
		if json.Unmarshal([]byte(subjectJSON), &subject) != nil || json.Unmarshal([]byte(superiorJSON), &superior) != nil {
			return
		}
		before := make(map[string]string, len(subject))
		for k, v := range subject {
			before[k] = string(v)
		}

		out, err := applySuperiorMetadata(subject, superior)

		for k, v := range subject {
			if before[k] != string(v) || len(before) != len(subject) {
				t.Fatalf("subject metadata modified")
			}
		}
		if err != nil {
			return
		}
		if len(out) != len(subject) {
			t.Fatalf("result has %d entity types, subject %d", len(out), len(subject))
		}
		for entityType, raw := range subject {
			result, ok := out[entityType]
			if !ok {
				t.Fatalf("entity type %q dropped", entityType)
			}
			override, overridden := superior[entityType]
			if !overridden || len(superior) == 0 {
				if string(result) != string(raw) {
					t.Fatalf("%s changed without a superior value", entityType)
				}
				continue
			}
			var params, overrides, merged map[string]json.RawMessage
			_ = json.Unmarshal(raw, &params)
			_ = json.Unmarshal(override, &overrides)
			if err := json.Unmarshal(result, &merged); err != nil {
				t.Fatalf("%s result is not a JSON object: %v", entityType, err)
			}
			for name, value := range overrides {
				if !jsonValuesEqual(t, merged[name], value) {
					t.Fatalf("%s.%s = %s, want the superior's %s", entityType, name, merged[name], value)
				}
			}
			for name, value := range params {
				if _, set := overrides[name]; !set && !jsonValuesEqual(t, merged[name], value) {
					t.Fatalf("%s.%s = %s, want the subject's %s", entityType, name, merged[name], value)
				}
			}
			if len(merged) != len(params)+countNew(overrides, params) {
				t.Fatalf("%s has %d parameters, want the subject's and the superior's", entityType, len(merged))
			}
		}
	})
}

func countNew(overrides, params map[string]json.RawMessage) int {
	n := 0
	for name := range overrides {
		if _, ok := params[name]; !ok {
			n++
		}
	}
	return n
}

func jsonValuesEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// FuzzValidEntityID checks ValidEntityID against OpenID Federation 1.0
// §1.2: an accepted Entity Identifier is an https URL with a host and
// optionally a port and path — no query, fragment or userinfo — and
// its well-known URL stays on that same host.
func FuzzValidEntityID(f *testing.F) {
	for _, seed := range []string{
		"https://rp.example.org", "https://rp.example.org/tenant/a", "https://rp.example.org:8443",
		"https://[::1]", "http://rp.example.org", "https://rp.example.org?x=1", "https://rp.example.org#",
		"https://u:p@rp.example.org", "https://", "https:///path",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, id string) {
		if ValidEntityID(id) != nil {
			return
		}
		u, err := url.Parse(id)
		if err != nil {
			t.Fatalf("accepted %q, which doesn't parse: %v", id, err)
		}
		if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(id, "#") || u.Opaque != "" {
			t.Fatalf("accepted %q: scheme %q, host %q, userinfo %v, query %q, fragment or opaque part", id, u.Scheme, u.Host, u.User, u.RawQuery)
		}
		wk, err := wellKnownURL(id)
		if err != nil {
			t.Fatalf("wellKnownURL(%q): %v", id, err)
		}
		if wk.Host != u.Host || wk.Scheme != "https" || !strings.HasSuffix(wk.Path, WellKnownPath) || wk.RawQuery != "" {
			t.Fatalf("wellKnownURL(%q) = %s leaves the entity's own host or path", id, wk)
		}
	})
}
