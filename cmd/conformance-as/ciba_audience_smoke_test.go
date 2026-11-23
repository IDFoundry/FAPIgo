package main

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
)

// suiteStyleCIBAClientID is a CIBA client whose client assertions name
// endpoint URLs, as the OIDF FAPI-CIBA suite's do.
const suiteStyleCIBAClientID = fapi.ClientID("suite-style-ciba-client")

// suiteStyleKeyID is the kid of suiteStyleCIBAClientID's one key.
const suiteStyleKeyID = "suite-style-key"

// suiteStyleAssertion signs a client assertion for
// suiteStyleCIBAClientID naming aud, with typ as its header's typ, or
// none, as the suite sends, when typ is empty.
func suiteStyleAssertion(t *testing.T, signer crypto.Signer, aud, typ string) string {
	t.Helper()
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss": suiteStyleCIBAClientID.String(), "sub": suiteStyleCIBAClientID.String(), "aud": aud,
		"jti": rand.Text(), "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, Type: typ, KeyID: suiteStyleKeyID}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return assertion
}

// suiteStyleBackchannelStatus posts to h's backchannel authentication
// endpoint a request object signed by signer for issuer, authenticated
// by suiteStyleAssertion naming aud with typ, and returns the status.
func suiteStyleBackchannelStatus(t *testing.T, h *smokeHarness, signer crypto.Signer, issuer fapi.URL, aud, typ string) int {
	t.Helper()
	request, err := requestobject.Create(requestobject.CreateParams{
		Signer: signer, Algorithm: fapi.ES256, KeyID: suiteStyleKeyID,
		ClientID: suiteStyleCIBAClientID.String(), Audience: issuer.String(),
		Now: time.Now(), Lifetime: 30 * time.Second,
		Parameters: map[string]json.RawMessage{"scope": json.RawMessage(`"openid accounts"`), "login_hint": json.RawMessage(`"` + smokeSubject + `"`)},
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}
	res, err := h.httpClient.PostForm(h.backchannelAuthenticate, url.Values{
		"client_assertion":      {suiteStyleAssertion(t, signer, aud, typ)},
		"client_assertion_type": {clientassertion.AssertionType},
		"request":               {request},
	})
	if err != nil {
		t.Fatalf("POST %s: %v", h.backchannelAuthenticate, err)
	}
	res.Body.Close()
	return res.StatusCode
}

// TestSmokeCIBAAcceptsTheSuitesEndpointAudiences: a -ciba conformance AS
// accepts, at the backchannel authentication endpoint, a client
// assertion with no typ naming the backchannel authentication endpoint
// URL, as the OIDF FAPI-CIBA suite's private_key_jwt modules sign it by
// default, or the token endpoint URL, as the second client of
// fapi-ciba-id1 and fapi-ciba-id1-refresh-token signs it, since
// wiring.go sets server.Config.CIBAEndpointURLAudiences; and still
// refuses one typed client-authentication+jwt, whose client follows
// RFC 10070.
func TestSmokeCIBAAcceptsTheSuitesEndpointAudiences(t *testing.T) {
	signer, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	jwk, err := jose.NewJWK(signer.Public(), fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(suiteStyleKeyID).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       suiteStyleCIBAClientID,
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	var issuer fapi.URL
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true, "", func(r *ResolvedConfig) {
		issuer = r.Issuer
		r.Clients = append(r.Clients, registered)
		r.ClientKeys = append(r.ClientKeys, ephemeral.ClientKeySpec{ClientID: suiteStyleCIBAClientID, JWKS: []byte(`{"keys":[` + string(jwkJSON) + `]}`)})
	})
	for _, tc := range []struct {
		name, aud, typ string
		want           int
	}{
		{"the backchannel authentication endpoint URL, untyped", h.backchannelAuthenticate, "", http.StatusOK},
		{"the token endpoint URL, untyped", h.token, "", http.StatusOK},
		{"the token endpoint URL, typed client-authentication+jwt", h.token, "client-authentication+jwt", http.StatusUnauthorized},
	} {
		if got := suiteStyleBackchannelStatus(t, h, signer, issuer, tc.aud, tc.typ); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
}
