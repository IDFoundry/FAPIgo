package client_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/requestobject"
)

// detailWithHTMLCharacters is an authorization_details entry holding <,
// > and &, which json.Marshal escapes as \u003c, \u003e and \u0026.
const detailWithHTMLCharacters = `{"type":"payment_initiation","creditorName":"A&B <Ltd>"}`

var detailsWithHTMLCharacters = []json.RawMessage{json.RawMessage(detailWithHTMLCharacters)}

// TestAuthorizationDetailsSentWithoutHTMLEscaping covers every request
// that carries authorization_details: each sends the caller's bytes as
// they were, as a form parameter or inside a signed request object,
// rather than re-escaped into a longer, differently spelled value the
// server then keeps byte for byte.
func TestAuthorizationDetailsSentWithoutHTMLEscaping(t *testing.T) {
	want := "[" + detailWithHTMLCharacters + "]"
	requestObjectParameter := func(t *testing.T, requestJWT string) string {
		t.Helper()
		obj, err := requestobject.Parse(requestJWT)
		if err != nil {
			t.Fatalf("parse request object: %v", err)
		}
		raw, ok := obj.Parameter("authorization_details")
		if !ok {
			t.Fatalf("request object is missing authorization_details")
		}
		return string(raw)
	}

	t.Run("PAR form", func(t *testing.T) {
		c, as, _ := newTestClient(t, false)
		if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
			Scope: []string{"openid"}, AuthorizationDetails: detailsWithHTMLCharacters,
		}); err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		if got := as.lastPARForm.Get("authorization_details"); got != want {
			t.Errorf("authorization_details = %s, want %s", got, want)
		}
	})
	t.Run("PAR request object", func(t *testing.T) {
		c, as, _ := newTestClient(t, true)
		if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
			Scope: []string{"openid"}, AuthorizationDetails: detailsWithHTMLCharacters,
		}); err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		if got := requestObjectParameter(t, as.lastPARForm.Get("request")); got != want {
			t.Errorf("authorization_details = %s, want %s", got, want)
		}
	})
	t.Run("CIBA request object", func(t *testing.T) {
		c, as, _ := newTestClientWithCIBA(t)
		if _, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
			Scope: []string{"openid"}, LoginHint: "user@example.com", AuthorizationDetails: detailsWithHTMLCharacters,
		}); err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		if got := requestObjectParameter(t, as.lastBCForm.Get("request")); got != want {
			t.Errorf("authorization_details = %s, want %s", got, want)
		}
	})
	t.Run("client_credentials form", func(t *testing.T) {
		c, as := newTestClientForClientCredentials(t, nil)
		if _, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{
			Scope: []string{"accounts"}, AuthorizationDetails: detailsWithHTMLCharacters,
		}); err != nil {
			t.Fatalf("RequestClientCredentialsToken: %v", err)
		}
		if got := as.lastForm.Get("authorization_details"); got != want {
			t.Errorf("authorization_details = %s, want %s", got, want)
		}
	})
}

// TestAuthorizationDetailsRefusedWithRepeatedMembers covers every
// request that carries authorization_details: an entry repeating a
// member, or holding two that differ only in case, at any depth, is
// invalid_request before anything is sent — authorization servers would
// read it differently, and a FAPIgo server refuses it, identical copies
// included — while the same detail without the repeat is sent.
func TestAuthorizationDetailsRefusedWithRepeatedMembers(t *testing.T) {
	plain := []json.RawMessage{json.RawMessage(`{"type":"payment_initiation","instructedAmount":{"amount":"1"}}`)}
	for name, details := range map[string][]json.RawMessage{
		"differing repeat": {json.RawMessage(`{"type":"payment_initiation","instructedAmount":{"amount":"1","amount":"1000"}}`)},
		"identical repeat": {json.RawMessage(`{"type":"payment_initiation","type":"payment_initiation"}`)},
		"case variant":     {plain[0], json.RawMessage(`{"type":"a","actions":[{"x":1,"X":1}]}`)},
	} {
		for request, send := range authorizationDetailsRequests(t) {
			if err := send(plain); err != nil {
				t.Fatalf("%s without a repeat: %v", request, err)
			}
			if code := clientErrorCode(t, send(details)); code != client.ErrorInvalidRequest {
				t.Errorf("%s, %s: error code = %q, want %q", request, name, code, client.ErrorInvalidRequest)
			}
		}
	}
}

// authorizationDetailsRequests sends each request that carries
// authorization_details with the details given.
func authorizationDetailsRequests(t *testing.T) map[string]func([]json.RawMessage) error {
	return map[string]func([]json.RawMessage) error{
		"PAR form": func(details []json.RawMessage) error {
			c, _, _ := newTestClient(t, false)
			_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, AuthorizationDetails: details})
			return err
		},
		"PAR request object": func(details []json.RawMessage) error {
			c, _, _ := newTestClient(t, true)
			_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, AuthorizationDetails: details})
			return err
		},
		"CIBA request object": func(details []json.RawMessage) error {
			c, _, _ := newTestClientWithCIBA(t)
			_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
				Scope: []string{"openid"}, LoginHint: "user@example.com", AuthorizationDetails: details,
			})
			return err
		},
		"client_credentials form": func(details []json.RawMessage) error {
			c, _ := newTestClientForClientCredentials(t, nil)
			_, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}, AuthorizationDetails: details})
			return err
		},
	}
}
