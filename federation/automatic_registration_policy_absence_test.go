package federation_test

import (
	"slices"
	"testing"
)

// The tests below are the policy-absence matrix for automatic
// registration: an RP leaving a parameter out, under each metadata
// policy operator a superior may set on it (OpenID Federation 1.0
// §6.1.3.1), at the Trust Anchor or an Intermediate, and under none. An
// operator that acts on an absent parameter (value, add, default)
// decides what the RP is registered with; one that only checks a
// present value (one_of, subset_of, superset_of, essential false) leaves
// the absent parameter's default, which one_of and subset_of narrow
// further where the default is the operator's own list; essential true
// refuses the RP.
// scope and subject_type, whose defaults under a policy are their own,
// aren't in it.

// grantTypesPolicy is a metadata policy setting operators on
// grant_types.
func grantTypesPolicy(operators string) string {
	return `{"openid_relying_party":{"grant_types":` + operators + `}}`
}

// TestAutomaticRegistrationGrantTypesAbsentUnderEachOperator: an RP
// leaving grant_types out is registered for the authorization code flow
// alone (RFC 7591 §2's default) unless a superior's value, add or
// default puts a grant in, and then only one every subset_of on the
// chain permits; a policy that checks values alone gives it nothing
// more, and essential refuses it. The operator allows client_credentials
// and CIBA throughout.
func TestAutomaticRegistrationGrantTypesAbsentUnderEachOperator(t *testing.T) {
	codeAndClientCreds := `["authorization_code","client_credentials"]`
	for _, tc := range []struct {
		name               string
		taPolicy, imPolicy string
		wantClientCreds    bool
		wantCIBA           bool
		wantRefused        bool
	}{
		{name: "no policy"},
		{name: "a policy on another parameter only", taPolicy: `{"openid_relying_party":{"token_endpoint_auth_method":{"one_of":["private_key_jwt"]}}}`},
		{name: "subset_of permitting every grant",
			taPolicy: grantTypesPolicy(`{"subset_of":["authorization_code","client_credentials","` + cibaGrantType + `"]}`)},
		{name: "subset_of the code flow", taPolicy: grantTypesPolicy(`{"subset_of":["authorization_code","refresh_token"]}`)},
		{name: "superset_of", taPolicy: grantTypesPolicy(`{"superset_of":["client_credentials"]}`)},
		{name: "essential false", taPolicy: grantTypesPolicy(`{"essential":false}`)},
		{name: "essential true", taPolicy: grantTypesPolicy(`{"essential":true}`), wantRefused: true},
		{name: "value null", taPolicy: grantTypesPolicy(`{"value":null}`)},
		{name: "value", taPolicy: grantTypesPolicy(`{"value":` + codeAndClientCreds + `}`), wantClientCreds: true},
		{name: "default", taPolicy: grantTypesPolicy(`{"default":` + codeAndClientCreds + `}`), wantClientCreds: true},
		{name: "Intermediate's default", imPolicy: grantTypesPolicy(`{"default":["authorization_code","` + cibaGrantType + `"]}`), wantCIBA: true},
		{name: "add", taPolicy: grantTypesPolicy(`{"add":["client_credentials"]}`), wantClientCreds: true},
		{name: "Intermediate's default under a Trust Anchor's subset_of withholding it",
			taPolicy: grantTypesPolicy(`{"subset_of":["authorization_code","refresh_token"]}`),
			imPolicy: grantTypesPolicy(`{"default":` + codeAndClientCreds + `}`)},
		{name: "Intermediate's default under a Trust Anchor's subset_of permitting it",
			taPolicy: grantTypesPolicy(`{"subset_of":` + codeAndClientCreds + `}`),
			imPolicy: grantTypesPolicy(`{"default":` + codeAndClientCreds + `}`), wantClientCreds: true},
		{name: "Intermediate's add under a Trust Anchor's subset_of withholding it",
			taPolicy: grantTypesPolicy(`{"subset_of":["authorization_code","refresh_token"]}`),
			imPolicy: grantTypesPolicy(`{"add":["client_credentials"]}`), wantRefused: true},
		{name: "one_of", taPolicy: grantTypesPolicy(`{"one_of":["client_credentials","` + cibaGrantType + `"]}`)},
		{name: "Intermediate's one_of", imPolicy: grantTypesPolicy(`{"one_of":[["client_credentials"]]}`)},
		{name: "Intermediate's default among a Trust Anchor's one_of",
			taPolicy: grantTypesPolicy(`{"one_of":[["authorization_code"],` + codeAndClientCreds + `]}`),
			imPolicy: grantTypesPolicy(`{"default":` + codeAndClientCreds + `}`), wantClientCreds: true},
		{name: "Intermediate's default outside a Trust Anchor's one_of",
			taPolicy: grantTypesPolicy(`{"one_of":[["authorization_code"]]}`),
			imPolicy: grantTypesPolicy(`{"default":` + codeAndClientCreds + `}`), wantRefused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := resolveWithGrantTypes(t, tc.taPolicy, tc.imPolicy, nil)
			if tc.wantRefused {
				if err == nil {
					t.Fatal("ResolveClient registered the RP, want it refused")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveClient: %v", err)
			}
			checkRegisteredGrants(t, client, tc.wantClientCreds, tc.wantCIBA)
		})
	}
}

// rarTypesPolicy is a metadata policy setting operators on
// authorization_details_types.
func rarTypesPolicy(operators string) string {
	return `{"openid_relying_party":{"authorization_details_types":` + operators + `}}`
}

// TestAutomaticRegistrationRARTypesAbsentUnderEachOperator: an RP
// leaving authorization_details_types out is registered for every Rich
// Authorization Request type the operator allows (payment and
// account_information here) that each superior's subset_of and one_of
// permit (a one_of's options listing the types it permits between
// them), unless a value, add or default sets the parameter, which then
// decides; a policy that only checks values otherwise narrows nothing,
// and essential refuses the RP.
func TestAutomaticRegistrationRARTypesAbsentUnderEachOperator(t *testing.T) {
	both, accounts := []string{"account_information", "payment"}, []string{"account_information"}
	for _, tc := range []struct {
		name               string
		taPolicy, imPolicy string
		want               []string // sorted; nil when the RP is refused
	}{
		{name: "no policy", want: both},
		{name: "a policy on another parameter only", taPolicy: `{"openid_relying_party":{"token_endpoint_auth_method":{"one_of":["private_key_jwt"]}}}`, want: both},
		{name: "subset_of permitting more", taPolicy: rarTypesPolicy(`{"subset_of":["account_information","payment","other"]}`), want: both},
		{name: "subset_of", taPolicy: rarTypesPolicy(`{"subset_of":["account_information"]}`), want: accounts},
		{name: "Intermediate's subset_of", imPolicy: rarTypesPolicy(`{"subset_of":["account_information"]}`), want: accounts},
		{name: "superset_of", taPolicy: rarTypesPolicy(`{"superset_of":["account_information"]}`), want: both},
		{name: "essential false", taPolicy: rarTypesPolicy(`{"essential":false}`), want: both},
		{name: "essential true", taPolicy: rarTypesPolicy(`{"essential":true}`)},
		{name: "value", taPolicy: rarTypesPolicy(`{"value":["account_information"]}`), want: accounts},
		{name: "value of none", taPolicy: rarTypesPolicy(`{"value":[]}`), want: []string{}},
		{name: "default", taPolicy: rarTypesPolicy(`{"default":["account_information"]}`), want: accounts},
		{name: "add", taPolicy: rarTypesPolicy(`{"add":["account_information"]}`), want: accounts},
		{name: "Intermediate's default under a Trust Anchor's subset_of withholding it",
			taPolicy: rarTypesPolicy(`{"subset_of":["account_information"]}`), imPolicy: rarTypesPolicy(`{"default":["payment"]}`), want: []string{}},
		{name: "Intermediate's add under a Trust Anchor's subset_of permitting it",
			taPolicy: rarTypesPolicy(`{"subset_of":["account_information","payment"]}`), imPolicy: rarTypesPolicy(`{"add":["payment"]}`), want: []string{"payment"}},
		{name: "Intermediate's add under a Trust Anchor's subset_of withholding it",
			taPolicy: rarTypesPolicy(`{"subset_of":["account_information"]}`), imPolicy: rarTypesPolicy(`{"add":["payment"]}`)},
		{name: "one_of", taPolicy: rarTypesPolicy(`{"one_of":["account_information"]}`), want: accounts},
		{name: "one_of permitting more", taPolicy: rarTypesPolicy(`{"one_of":[["account_information"],["payment","other"]]}`), want: both},
		{name: "Intermediate's one_of", imPolicy: rarTypesPolicy(`{"one_of":["account_information","other"]}`), want: accounts},
		{name: "one_of at both, intersected",
			taPolicy: rarTypesPolicy(`{"one_of":["account_information","payment"]}`), imPolicy: rarTypesPolicy(`{"one_of":["account_information","other"]}`), want: accounts},
		{name: "Intermediate's default among a Trust Anchor's one_of",
			taPolicy: rarTypesPolicy(`{"one_of":[["account_information"],["payment"]]}`), imPolicy: rarTypesPolicy(`{"default":["payment"]}`), want: []string{"payment"}},
		{name: "Intermediate's default outside a Trust Anchor's one_of",
			taPolicy: rarTypesPolicy(`{"one_of":[["account_information"]]}`), imPolicy: rarTypesPolicy(`{"default":["payment"]}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := resolveWithRARTypes(t, tc.taPolicy, tc.imPolicy, map[string]any{
				"redirect_uris":                   []string{"https://rp.example.org/cb"},
				"token_endpoint_auth_method":      "private_key_jwt",
				"token_endpoint_auth_signing_alg": "ES256",
			})
			if tc.want == nil {
				if err == nil {
					t.Fatalf("ResolveClient registered %q, want the RP refused", client.AuthorizationDetailsTypes())
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveClient: %v", err)
			}
			if got := client.AuthorizationDetailsTypes(); !slices.Equal(got, tc.want) {
				t.Errorf("AuthorizationDetailsTypes() = %q, want %q", got, tc.want)
			}
		})
	}
}
