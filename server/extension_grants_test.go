package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const preAuthorizedCodeGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// extensionTokenRequest is an embedder's token request for the
// pre-authorized code grant, read the way an embedder reads one: through
// TokenEndpointRequestFromHTTP.
func extensionTokenRequest(t *testing.T, form url.Values, header http.Header, cert *x509.Certificate) server.TokenEndpointRequest {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, testTokenEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, values := range header {
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("TokenEndpointRequestFromHTTP: %v", err)
	}
	return req
}

func preAuthorizedForm() url.Values {
	return url.Values{"grant_type": {preAuthorizedCodeGrant}, "pre-authorized_code": {"code-1"}, "tx_code": {"1234"}}
}

func dpopHeader(proofs ...string) http.Header {
	return http.Header{"Dpop": proofs}
}

func dpopProofAt(t *testing.T, key *ecdsa.PrivateKey, target, nonce string, now time.Time) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: u, Now: now, Nonce: nonce})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	return proof
}

func registeredClient(t *testing.T, h harness) storage.RegisteredClient {
	t.Helper()
	client, err := h.clients.ResolveClient(context.Background(), testClientID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestTokenEndpointRequestParameters(t *testing.T) {
	req := extensionTokenRequest(t, preAuthorizedForm(), nil, nil)
	if req.GrantType() != preAuthorizedCodeGrant {
		t.Fatalf("GrantType() = %q", req.GrantType())
	}
	params, err := req.Parameters()
	if err != nil {
		t.Fatalf("Parameters: %v", err)
	}
	if params["pre-authorized_code"] != "code-1" || params["tx_code"] != "1234" {
		t.Errorf("Parameters() = %v", params)
	}

	form := preAuthorizedForm()
	form.Add("tx_code", "5678")
	_, err = extensionTokenRequest(t, form, nil, nil).Parameters()
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Errorf("Parameters(repeated tx_code) error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

// TestExtensionGrantAuthenticationAndBinding covers an embedder's grant
// end to end: the request read once, the client authenticated by its
// attestation, and the DPoP proof bound.
func TestExtensionGrantAuthenticationAndBinding(t *testing.T) {
	attesterKey, instanceKey, dpopKey := generateKey(t), generateKey(t), generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	header := dpopHeader(dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now))
	header.Set("OAuth-Client-Attestation", createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour))
	header.Set("OAuth-Client-Attestation-PoP", createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now))
	req := extensionTokenRequest(t, preAuthorizedForm(), header, nil)

	attested, err := h.server.AuthenticateAttestedClient(context.Background(), req.AttestedClientAuthentication())
	if err != nil {
		t.Fatalf("AuthenticateAttestedClient: %v", err)
	}
	binding, err := h.server.VerifyTokenRequestBinding(context.Background(), attested.Client, req)
	if err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	want, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Thumbprint != want.String() || binding.SenderConstrain != storage.SenderConstrainDPoP || binding.NextDPoPNonce != "" {
		t.Errorf("binding = %+v, want the DPoP key's thumbprint %s and no nonce", binding, want)
	}
	events := h.audit.all()
	if last := events[len(events)-1]; last.Type != server.AuditEventVerifyTokenRequestBinding || last.Outcome != server.AuditOutcomeSuccess {
		t.Errorf("last audit event = %+v, want a VerifyTokenRequestBinding success", last)
	}
}

func TestVerifyTokenRequestBindingRefusesBadDPoP(t *testing.T) {
	dpopKey := generateKey(t)
	for name, proofs := range map[string]func(now time.Time) []string{
		"no proof": func(time.Time) []string { return nil },
		"two proofs": func(now time.Time) []string {
			return []string{dpopProofAt(t, dpopKey, testTokenEndpoint, "", now), dpopProofAt(t, dpopKey, testTokenEndpoint, "", now)}
		},
		"another endpoint": func(now time.Time) []string {
			return []string{dpopProofAt(t, dpopKey, "https://as.example/par", "", now)}
		},
		"stale proof": func(now time.Time) []string {
			return []string{dpopProofAt(t, dpopKey, testTokenEndpoint, "", now.Add(-time.Hour))}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttestationClientCredentials(t, generateKey(t))
			req := extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(proofs(h.now)...), nil)
			_, err := h.server.VerifyTokenRequestBinding(context.Background(), registeredClient(t, h), req)
			var serr *server.Error
			if !errors.As(err, &serr) || serr.HTTPStatus() != 400 {
				t.Fatalf("VerifyTokenRequestBinding = %v, want a 400 refusal", err)
			}
			if last := h.audit.all(); len(last) == 0 || last[len(last)-1].Outcome != server.AuditOutcomeFailure {
				t.Errorf("audit = %+v, want a failure recorded", last)
			}
		})
	}
}

// TestVerifyTokenRequestBindingSharesDPoPReplay covers one DPoP replay
// record for the whole token endpoint: a proof the server's own grant
// accepted is refused for the embedder's, and the other way round.
func TestVerifyTokenRequestBindingSharesDPoPReplay(t *testing.T) {
	attesterKey, instanceKey, dpopKey := generateKey(t), generateKey(t), generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	proof := dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)
	if _, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)},
		ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now)},
		DPoPProofs:            []string{proof},
	}); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	req := extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(proof), nil)
	if _, err := h.server.VerifyTokenRequestBinding(context.Background(), registeredClient(t, h), req); serverErrorCode(t, err) != server.ErrorInvalidDPoPProof {
		t.Fatalf("VerifyTokenRequestBinding(proof already used) = %v, want invalid_dpop_proof", err)
	}

	second := dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)
	if _, err := h.server.VerifyTokenRequestBinding(context.Background(), registeredClient(t, h), extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(second), nil)); err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)},
		ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-2", h.now)},
		DPoPProofs:            []string{second},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidDPoPProof {
		t.Fatalf("RequestClientCredentialsToken(proof used by the embedder's grant) = %v, want invalid_dpop_proof", err)
	}
}

func TestVerifyTokenRequestBindingAtTheMTLSAlias(t *testing.T) {
	const alias = "https://mtls.as.example/token"
	h := newAttestationHarness(t, time.Now(), generateKey(t), server.RegisteredAttesterKeys{}, func(cfg *server.Config, _ *storage.RegisteredClientConfig) {
		u, err := fapi.ParseEndpointURL(alias)
		if err != nil {
			t.Fatal(err)
		}
		cfg.MTLSEndpoints.Token = u
	})
	req := extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(dpopProofAt(t, generateKey(t), alias, "", h.now)), nil)
	if _, err := h.server.VerifyTokenRequestBinding(context.Background(), registeredClient(t, h), req); err != nil {
		t.Fatalf("VerifyTokenRequestBinding(proof for the mTLS alias): %v", err)
	}
}

func TestVerifyTokenRequestBindingNonces(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)
	client := registeredClient(t, h)

	req := extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(dpopProofAt(t, dpopKey, testTokenEndpoint, "", h.now)), nil)
	_, err := h.server.VerifyTokenRequestBinding(context.Background(), client, req)
	var challenge *server.Error
	if !errors.As(err, &challenge) || challenge.Code() != server.ErrorUseDPoPNonce || challenge.Nonce() == "" {
		t.Fatalf("VerifyTokenRequestBinding(no nonce) = %v, want use_dpop_nonce carrying a nonce", err)
	}

	req = extensionTokenRequest(t, preAuthorizedForm(), dpopHeader(dpopProofAt(t, dpopKey, testTokenEndpoint, challenge.Nonce(), h.now)), nil)
	binding, err := h.server.VerifyTokenRequestBinding(context.Background(), client, req)
	if err != nil {
		t.Fatalf("VerifyTokenRequestBinding(with the nonce): %v", err)
	}
	if binding.NextDPoPNonce == "" {
		t.Error("NextDPoPNonce is empty, want the nonce to use next")
	}
}

func TestVerifyTokenRequestBindingMTLS(t *testing.T) {
	h := newAttestationHarness(t, time.Now(), generateKey(t), server.RegisteredAttesterKeys{}, func(_ *server.Config, c *storage.RegisteredClientConfig) {
		c.SenderConstrain = storage.SenderConstrainMTLS
	})
	cert := newTestCert(t, "client", certOptions{}).cert
	binding, err := h.server.VerifyTokenRequestBinding(context.Background(), registeredClient(t, h), extensionTokenRequest(t, preAuthorizedForm(), nil, cert))
	if err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	if binding.Thumbprint != mtls.Thumbprint(cert) || binding.SenderConstrain != storage.SenderConstrainMTLS {
		t.Errorf("binding = %+v, want the certificate's thumbprint", binding)
	}
	if _, err := h.server.VerifyTokenRequestBinding(context.Background(), registeredClient(t, h), extensionTokenRequest(t, preAuthorizedForm(), nil, nil)); serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Errorf("VerifyTokenRequestBinding(no certificate) = %v, want invalid_request", err)
	}
}

func TestAdditionalGrantTypesAdvertised(t *testing.T) {
	h := newAttestationHarness(t, time.Now(), generateKey(t), server.RegisteredAttesterKeys{}, func(cfg *server.Config, _ *storage.RegisteredClientConfig) {
		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
	})
	got := h.server.Metadata(context.Background()).GrantTypesSupported
	if len(got) == 0 || got[len(got)-1] != preAuthorizedCodeGrant {
		t.Errorf("grant_types_supported = %v, want %s after the server's own", got, preAuthorizedCodeGrant)
	}
}
