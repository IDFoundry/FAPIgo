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
