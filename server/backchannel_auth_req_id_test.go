package server_test

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// unknownAuthReqID has the form this server gives an auth_req_id, but
// names no request.
const unknownAuthReqID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// boundDigestPreimage is the auth_req_id an attacker holding the
// client's assertion key, but not the client instance or DPoP key,
// crafts for the request authReqID names, bound to instanceKey and
// dpopJKT: the string the request's digest is taken over, whose own
// unbound digest is that digest.
func boundDigestPreimage(t *testing.T, authReqID, instanceKey, dpopJKT string) string {
	t.Helper()
	preimage, ok := server.BoundAuthReqIDPreimage(authReqID, instanceKey, dpopJKT)
	if !ok {
		t.Fatal("the bound digest's preimage has another unbound digest, so there's nothing left to refuse")
	}
	return preimage
}

func newCountingBackchannelHarness(t *testing.T) (harness, *countingBackchannelStore) {
	t.Helper()
	store := &countingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	return newHarnessWithBackchannelStore(t, store), store
}

// beginDPoPBoundBackchannel makes a CIBA request bound to key: by a
// dpop_jkt naming it when explicit, and otherwise by a DPoP proof from
// key, as the bundled client sends one.
func beginDPoPBoundBackchannel(t *testing.T, h harness, key *ecdsa.PrivateKey, explicit bool) server.BackchannelInteractionRequired {
	t.Helper()
	params := standardBackchannelParams(t)
	if explicit {
		params["dpop_jkt"] = jsonRaw(t, dpopThumbprint(t, key))
		return beginBackchannel(t, h, params)
	}
	endpoint, err := url.Parse(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: endpoint, Now: h.now})
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP:       server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
		DPoPProofs: []string{proof},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}
	return required
}

// exchangeBackchannelOverHTTP is exchangeBackchannelWithKey for a token
// request read from a form-encoded HTTP request
// (TokenEndpointRequestFromHTTP), as an HTTP token endpoint receives it.
func exchangeBackchannelOverHTTP(t *testing.T, h harness, authReqID string, key *ecdsa.PrivateKey) error {
	t.Helper()
	form := url.Values{
		"client_assertion":      {h.clientAssertion(t)},
		"client_assertion_type": {clientassertion.AssertionType},
		"grant_type":            {server.CIBAGrantType},
		"auth_req_id":           {authReqID},
	}
	r := httptest.NewRequest(http.MethodPost, testTokenEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("DPoP", createDPoPProof(t, key, h.now))
	request, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("TokenEndpointRequestFromHTTP: %v", err)
	}
	_, err = h.server.ExchangeBackchannelAuthentication(context.Background(), request.BackchannelTokenExchange())
	return err
}

// writtenTokenError is err as the token endpoint writes it
// (server.WriteError): its status line, headers and body.
func writtenTokenError(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("the token request succeeded, want an error")
	}
	rec := httptest.NewRecorder()
	server.WriteError(rec, err)
	dump, dumpErr := httputil.DumpResponse(rec.Result(), true)
	if dumpErr != nil {
		t.Fatalf("DumpResponse: %v", dumpErr)
	}
	return string(dump)
}

// requireAnsweredAsUnknownUnpolled fails t unless the token request
// present makes with value is answered exactly as one with an
// auth_req_id naming no request is, without store being polled.
func requireAnsweredAsUnknownUnpolled(t *testing.T, store *countingBackchannelStore, present func(t *testing.T, authReqID string) error, value string) {
	t.Helper()
	unknown := writtenTokenError(t, present(t, unknownAuthReqID))
	polled := store.polled
	if got := writtenTokenError(t, present(t, value)); got != unknown {
		t.Fatalf("%q answered\n%s\nwant the answer for an auth_req_id naming no request\n%s", value, got, unknown)
	}
	if n := store.polled - polled; n != 0 {
		t.Fatalf("%q was polled for %d times, want none", value, n)
	}
}

// TestExchangeBackchannelAuthenticationRefusesMalformedAuthReqID: a
// value of another form than the 43 base64url characters this server
// gives an auth_req_id names no request, so it's answered exactly as an
// unknown auth_req_id is, invalid_grant, but without the store being
// polled for it. So it doesn't count as a poll of a pending request
// either: the request's own first poll afterwards is
// authorization_pending, not slow_down.
func TestExchangeBackchannelAuthenticationRefusesMalformedAuthReqID(t *testing.T) {
	h, store := newCountingBackchannelHarness(t)
	bound := generateKey(t)
	required := beginDPoPBoundBackchannel(t, h, bound, true)
	id := required.AuthReqID.String()
	present := func(t *testing.T, authReqID string) error {
		return exchangeBackchannelWithKey(t, h, authReqID, generateKey(t))
	}

	if err := present(t, unknownAuthReqID); serverErrorCode(t, err) != server.ErrorInvalidGrant || store.polled == 0 {
		t.Fatalf("an unknown auth_req_id: %v after %d polls, want invalid_grant after polling for it", err, store.polled)
	}
	for name, value := range map[string]string{
		"42 characters":         id[:42],
		"44 characters":         id + "A",
		"NUL":                   id[:42] + "\x00",
		"space":                 " " + id[1:],
		"plus":                  id[:42] + "+",
		"bound digest preimage": boundDigestPreimage(t, id, "", dpopThumbprint(t, bound)),
	} {
		t.Run(name, func(t *testing.T) {
			requireAnsweredAsUnknownUnpolled(t, store, present, value)
		})
	}
	if code := serverErrorCode(t, exchangeBackchannelWithKey(t, h, id, bound)); code != server.ErrorAuthorizationPending {
		t.Fatalf("the request's own first poll = %s, want authorization_pending", code)
	}
}

// TestCraftedAuthReqIDLeavesTheBoundApproval: the client's own
// assertion key, without the client instance or DPoP key an approved
// request is bound to, can't spend its approval by presenting the
// string the request's digest is taken over, whose unbound digest is
// the same: it's refused as an unknown auth_req_id, before any poll, so
// the instance and key the request is bound to still redeem it. That
// holds for a dpop_jkt, for the key of a DPoP proof sent with the
// request, with the NUL the string starts with sent as %00 over HTTP,
// and for a client instance.
func TestCraftedAuthReqIDLeavesTheBoundApproval(t *testing.T) {
	for name, tc := range map[string]struct {
		explicit, overHTTP bool
	}{
		"dpop_jkt":              {explicit: true},
		"DPoP proof":            {},
		"DPoP proof, over HTTP": {overHTTP: true},
	} {
		t.Run(name, func(t *testing.T) {
			h, store := newCountingBackchannelHarness(t)
			bound := generateKey(t)
			required := beginDPoPBoundBackchannel(t, h, bound, tc.explicit)
			approveBackchannel(t, h, required.Handle)
			crafted := boundDigestPreimage(t, required.AuthReqID.String(), "", dpopThumbprint(t, bound))
			present := func(t *testing.T, authReqID string) error {
				return exchangeBackchannelWithKey(t, h, authReqID, generateKey(t))
			}
			if tc.overHTTP {
				if body := (url.Values{"auth_req_id": {crafted}}).Encode(); !strings.Contains(body, "%00") {
					t.Fatalf("form body %q carries no %%00", body)
				}
				present = func(t *testing.T, authReqID string) error {
					return exchangeBackchannelOverHTTP(t, h, authReqID, generateKey(t))
				}
			}

			requireAnsweredAsUnknownUnpolled(t, store, present, crafted)
			if err := exchangeBackchannelWithKey(t, h, required.AuthReqID.String(), bound); err != nil {
				t.Fatalf("the bound key's poll afterwards: %v, want tokens", err)
			}
		})
	}
	t.Run("client instance", func(t *testing.T) {
		attesterKey := generateKey(t)
		store := &countingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
		h := newBackchannelInstanceBindingHarnessWithStore(t, attesterKey, store)
		requester := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
		required := requester.beginBackchannel()
		approveBackchannel(t, h, required.Handle)
		crafted := boundDigestPreimage(t, required.AuthReqID.String(), dpopThumbprint(t, requester.instanceKey), "")

		// private_key_jwt, which authenticates no client instance.
		present := func(t *testing.T, authReqID string) error {
			return exchangeBackchannelWithKey(t, h, authReqID, generateKey(t))
		}
		requireAnsweredAsUnknownUnpolled(t, store, present, crafted)
		if _, err := requester.exchangeBackchannel(required.AuthReqID.String(), generateKey(t)); err != nil {
			t.Fatalf("the requesting instance's poll afterwards: %v, want tokens", err)
		}
	})
}
