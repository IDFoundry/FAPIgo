package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestMalformedClaimsParameterIsRefused: a claims parameter that isn't a
// JSON object is invalid_request at PAR and at the backchannel
// authentication endpoint, rather than read as no claims at all.
func TestMalformedClaimsParameterIsRefused(t *testing.T) {
	for name, claims := range map[string]string{
		"not JSON": `{"id_token":`,
		// A case variant of a member: its members are case-sensitive,
		// so it's refused rather than silently honoured or ignored.
		"ID_TOKEN":  `{"ID_TOKEN":{"acr":{"essential":true,"values":["gold"]}}}`,
		"Essential": `{"id_token":{"acr":{"Essential":true,"values":["gold"]}}}`,
	} {
		t.Run("PAR "+name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"claims": claims})},
			})
			if serverErrorCode(t, err) != server.ErrorInvalidRequest {
				t.Fatalf("PAR with claims %s: %v, want invalid_request", claims, err)
			}
		})
	}
	t.Run("CIBA", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		params := standardBackchannelParams(t)
		params["claims"] = jsonRaw(t, []string{"email"})
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
		})
		if err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		localErr, ok := action.(server.BackchannelAuthenticationLocalError)
		if !ok || localErr.Error.Code() != server.ErrorInvalidRequest {
			t.Fatalf("action = %#v, want invalid_request", action)
		}
	})
}

// newProductionBackchannelHarness is newHarnessWithBackchannel under
// AssuranceProduction, with the store capabilities and dependencies it
// requires.
func newProductionBackchannelHarness(t *testing.T) harness {
	t.Helper()
	return newHarnessWithBackchannelOptions(t, declaredBackchannelStore{memstore.NewBackchannelAuthenticationStore()},
		func(c *server.Config) {
			asProduction(c)
			c.Deployment = server.DeploymentSingleInstance
		},
		func(d *server.Dependencies) {
			d.Audit = &fakeAuditSink{}
			d.Nonces = server.NoDPoPNonces{}
			d.ClientCertificateTrust = server.ClientCertificateChainVerifiedUpstream{}
		})
}

// TestClientRequestRefusesDoublyEncodedClaimsParameter: under
// AssuranceProduction, a "claims" parameter JSON-encoded twice (a PAR
// form value that is itself a JSON string, or a signed request's member
// holding a string that holds one) is refused with invalid_request.
// Every reader unwraps one string layer, so it would read such a value
// as no claims at all, and the essential acr and sub value it asks for
// would go unenforced. The encodings OIDC Core §5.5 provides are still
// accepted: the object's text as a form value, and the object, or a
// string holding it, as a signed request's member.
func TestClientRequestRefusesDoublyEncodedClaimsParameter(t *testing.T) {
	const claims = `{"id_token":{"acr":{"essential":true,"values":["urn:gold"]},"sub":{"value":"intended-user"}}}`
	once := asJSONString(claims)
	twice := asJSONString(once)
	pushForm := func(t *testing.T, value string) error {
		return pushPlainClaimsTo(t, newHarnessWithRedirectURI(t, server.ProfileFAPISecurity, true, testRedirectURI, server.AssuranceProduction), value)
	}
	pushRequestObject := func(t *testing.T, member string) error {
		return pushClaimsRequestObjectTo(t, newHarnessWithRedirectURI(t, server.ProfileFAPISecurity, true, testRedirectURI, server.AssuranceProduction), member)
	}
	beginBackchannel := func(t *testing.T, member string) error {
		return beginBackchannelWithRawParameter(t, newProductionBackchannelHarness(t), "claims", member)
	}
	for _, tc := range []struct {
		name    string
		request func(*testing.T, string) error
		value   string
		refused bool
	}{
		{"PAR form, the object's text", pushForm, claims, false},
		{"PAR form, a JSON string", pushForm, once, true},
		{"PAR request object, the object", pushRequestObject, claims, false},
		{"PAR request object, a string holding the object", pushRequestObject, once, false},
		{"PAR request object, a string holding a JSON string", pushRequestObject, twice, true},
		{"CIBA, the object", beginBackchannel, claims, false},
		{"CIBA, a string holding the object", beginBackchannel, once, false},
		{"CIBA, a string holding a JSON string", beginBackchannel, twice, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.request(t, tc.value)
			if !tc.refused {
				if err != nil {
					t.Fatalf("claims %s refused: %v", tc.value, err)
				}
				return
			}
			assertRequestErrorCode(t, tc.name, err, server.ErrorInvalidRequest)
		})
	}
}
