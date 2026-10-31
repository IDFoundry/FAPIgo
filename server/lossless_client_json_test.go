package server_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// lossyJSONStrings are JSON strings encoding/json reads as something
// else: it replaces invalid UTF-8, and a \u escape of an unpaired
// surrogate, with U+FFFD.
var lossyJSONStrings = map[string]string{
	"invalid UTF-8":             "\"SGD \xff\"",
	"unpaired surrogate escape": `"SGD \ud800"`,
}

// losslessJSONStrings are non-ASCII JSON strings that decode as written.
var losslessJSONStrings = map[string]string{
	"euro sign":             `"SGD €"`,
	"e acute":               `"é"`,
	"emoji":                 `"😀"`,
	"surrogate pair escape": `"😀"`,
}

// lossyPlaceholder stands in a signed request's parameters for a value
// resignWithRawValue then swaps in.
const lossyPlaceholder = `"lossy-placeholder"`

// resignWithRawValue returns the ES256 request object compact with its
// payload's lossyPlaceholder replaced by raw and signed again with key:
// requestobject.Create, like every signer here, refuses to sign a
// payload encoding/json would alter, so a client sending one is
// simulated by hand.
func resignWithRawValue(t *testing.T, compact string, key *ecdsa.PrivateKey, raw string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("request object %q is not a compact JWS", compact)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !bytes.Contains(payload, []byte(lossyPlaceholder)) {
		t.Fatalf("payload %s has no placeholder", payload)
	}
	payload = bytes.Replace(payload, []byte(lossyPlaceholder), []byte(raw), 1)
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:crypto.SHA256.Size()])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func mintedDetailsWithAction(action string) string {
	return `[{"type":"minted","actions":[` + action + `]}]`
}

// pushMintedRequestObject pushes a request object whose
// authorization_details is raw, signed as sent.
func pushMintedRequestObject(t *testing.T, raw string) error {
	t.Helper()
	h := mintedRARHarness(t)
	params := standardAuthParams(t)
	params["authorization_details"] = json.RawMessage(lossyPlaceholder)
	obj := resignWithRawValue(t, h.requestObject(t, params), h.key, raw)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", obj),
		}},
	})
	return err
}

// beginBackchannelWithRawParameter begins a CIBA request whose signed
// request carries raw, as sent, under name.
func beginBackchannelWithRawParameter(t *testing.T, h harness, name, raw string) error {
	t.Helper()
	params := standardBackchannelParams(t)
	params[name] = json.RawMessage(lossyPlaceholder)
	obj := resignWithRawValue(t, h.backchannelRequestObject(t, params), h.key, raw)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), obj)},
	})
	if err != nil {
		return err
	}
	if localErr, ok := action.(server.BackchannelAuthenticationLocalError); ok {
		return localErr.Error
	}
	return nil
}

func beginMintedBackchannelRaw(t *testing.T, raw string) error {
	t.Helper()
	return beginBackchannelWithRawParameter(t, mintedRARHarness(t), "authorization_details", raw)
}

// assertRequestErrorCode checks err is a 400 with code want.
func assertRequestErrorCode(t *testing.T, name string, err error, want server.ErrorCode) {
	t.Helper()
	var srvErr *server.Error
	if !errors.As(err, &srvErr) {
		t.Fatalf("%s: error = %v, want a *server.Error %s", name, err, want)
	}
	if srvErr.Code() != want || srvErr.HTTPStatus() != 400 {
		t.Fatalf("%s: error = %d %q, want 400 %q (%v)", name, srvErr.HTTPStatus(), srvErr.Code(), want, err)
	}
}

// authorizationDetailsFlows are the requests a client starts a grant
// with authorization_details by, and the error each refuses a value
// encoding/json would alter with: invalid_authorization_details from
// RARRegistry.ParseRequest for a form parameter, and from the request
// object's own check (the JWS parser refuses such a payload) for a
// signed request.
var authorizationDetailsFlows = []struct {
	name    string
	request func(*testing.T, string) error
	lossy   server.ErrorCode
}{
	{"PAR form", pushMintedRequest, server.ErrorInvalidAuthorizationDetails},
	{"PAR request object", pushMintedRequestObject, server.ErrorInvalidRequestObject},
	{"CIBA", beginMintedBackchannelRaw, server.ErrorInvalidRequest},
	{"client_credentials", requestMintedClientCredentials, server.ErrorInvalidAuthorizationDetails},
}

// TestClientRequestRefusesLossyAuthorizationDetails: authorization_details
// a client sends that encoding/json would alter is refused with a 400
// when the client sends it, not accepted to fail with server_error once
// a token carrying it can't be signed. Non-ASCII that decodes as written
// is still accepted.
func TestClientRequestRefusesLossyAuthorizationDetails(t *testing.T) {
	for _, flow := range authorizationDetailsFlows {
		t.Run(flow.name, func(t *testing.T) {
			for name, value := range lossyJSONStrings {
				assertRequestErrorCode(t, name, flow.request(t, mintedDetailsWithAction(value)), flow.lossy)
			}
			for name, value := range losslessJSONStrings {
				if err := flow.request(t, mintedDetailsWithAction(value)); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			}
		})
	}
}

// rarLossyGranted is a grant holding a real U+FFFD, which a lossy
// decoding of "SGD \xff" or "SGD \ud800" would equal, and non-ASCII a
// client narrows to with escapes.
const rarLossyGranted = `[{"type":"payment","actions":["approve"],"amount":"SGD ` + "�" + `"},{"type":"payment","actions":["approve"],"amount":"é 😀"}]`

func paymentAmountDetails(amount string) string {
	return `[{"type":"payment","actions":["approve"],"amount":` + amount + `}]`
}

// TestTokenRequestRefusesLossyAuthorizationDetails: a token request's
// authorization_details, narrowing the grant, is refused with
// invalid_authorization_details when encoding/json would alter it, even
// when its altered reading equals a granted object; escaped non-ASCII
// equal to a granted object still narrows.
func TestTokenRequestRefusesLossyAuthorizationDetails(t *testing.T) {
	h := rarTokenRequestHarness(t)
	first, err := rarExchangeCode(t, h, rarIssueCodeFor(t, h, rarLossyGranted), nil)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	refreshToken := first.RefreshToken.Reveal()

	for name, value := range lossyJSONStrings {
		t.Run(name, func(t *testing.T) {
			details := paymentAmountDetails(value)
			_, err := rarExchangeCode(t, h, rarIssueCodeFor(t, h, rarLossyGranted), &details)
			assertInvalidAuthorizationDetails(t, err)
			_, err = rarRefresh(t, h, refreshToken, &details)
			assertInvalidAuthorizationDetails(t, err)
		})
	}
	for amount, want := range map[string]string{`"é 😀"`: "é 😀", `"SGD �"`: "SGD �"} {
		details := paymentAmountDetails(amount)
		want := []testPaymentDetail{{Amount: want}}
		result, err := rarExchangeCode(t, h, rarIssueCodeFor(t, h, rarLossyGranted), &details)
		if err != nil {
			t.Fatalf("ExchangeAuthorizationCode narrowing to %s: %v", amount, err)
		}
		assertIssuedAuthorizationDetails(t, h, result, want)
		if result, err = rarRefresh(t, h, refreshToken, &details); err != nil {
			t.Fatalf("RefreshAccessToken narrowing to %s: %v", amount, err)
		}
		assertIssuedAuthorizationDetails(t, h, result, want)
	}
}

func claimsRequestingSub(value string) string {
	return `{"id_token":{"sub":{"value":` + value + `}}}`
}

// pushPlainClaims pushes value as a plain form "claims" parameter.
func pushPlainClaims(t *testing.T, value string) error {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"claims": value})},
	})
	return err
}

// pushClaimsRequestObject pushes a request object whose "claims" member
// is raw, signed as sent.
func pushClaimsRequestObject(t *testing.T, raw string) error {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := standardAuthParams(t)
	params["claims"] = json.RawMessage(lossyPlaceholder)
	obj := resignWithRawValue(t, h.requestObject(t, params), h.key, raw)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", obj),
		}},
	})
	return err
}

func beginBackchannelClaims(t *testing.T, raw string) error {
	t.Helper()
	return beginBackchannelWithRawParameter(t, mintedRARHarness(t), "claims", raw)
}

// asJSONString returns text as a JSON string, as a request object may
// carry "claims", escaping only '"' and '\': text's own escapes then
// reach the claims object as written.
func asJSONString(text string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}

// claimsFlows are the ways a client sends the "claims" parameter, as a
// function of the claims object's JSON text, and the error each refuses
// one encoding/json would alter with.
var claimsFlows = []struct {
	name    string
	request func(*testing.T, string) error
	lossy   server.ErrorCode
}{
	{"PAR form", pushPlainClaims, server.ErrorInvalidRequest},
	{"PAR request object", pushClaimsRequestObject, server.ErrorInvalidRequestObject},
	{"PAR request object string", func(t *testing.T, claims string) error {
		return pushClaimsRequestObject(t, asJSONString(claims))
	}, server.ErrorInvalidRequest},
	{"CIBA", beginBackchannelClaims, server.ErrorInvalidRequest},
	{"CIBA string", func(t *testing.T, claims string) error {
		return beginBackchannelClaims(t, asJSONString(claims))
	}, server.ErrorInvalidRequest},
}

// TestClientRequestRefusesLossyClaimsParameter: a "claims" parameter
// encoding/json would alter is refused with invalid_request (or, inside
// a PAR request object the JWS parser refuses, invalid_request_object),
// so a requested sub of "SGD \xff" doesn't match a user whose sub is
// "SGD �". Non-ASCII that decodes as written is still accepted.
func TestClientRequestRefusesLossyClaimsParameter(t *testing.T) {
	for _, flow := range claimsFlows {
		t.Run(flow.name, func(t *testing.T) {
			for name, value := range lossyJSONStrings {
				if strings.HasSuffix(flow.name, "string") && name == "invalid UTF-8" {
					// The request object's own payload would then be
					// invalid UTF-8: the "request object" flow covers it.
					continue
				}
				assertRequestErrorCode(t, name, flow.request(t, claimsRequestingSub(value)), flow.lossy)
			}
			for name, value := range losslessJSONStrings {
				if err := flow.request(t, claimsRequestingSub(value)); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			}
		})
	}
}
