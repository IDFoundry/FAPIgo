package server_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// attestedClientRequest is a request carrying one attestation, made by
// attesterKey for testClientID and bound to instanceKey, and one PoP
// for it.
func attestedClientRequest(t *testing.T, h harness, attesterKey, instanceKey *ecdsa.PrivateKey, jti string) server.AttestedClientAuthenticationRequest {
	t.Helper()
	return server.AttestedClientAuthenticationRequest{
		ClientAttestations:    []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)},
		ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, jti, h.now)},
	}
}

func TestAuthenticateAttestedClient(t *testing.T) {
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)

	got, err := h.server.AuthenticateAttestedClient(context.Background(), attestedClientRequest(t, h, attesterKey, instanceKey, "jti-1"))
	if err != nil {
		t.Fatalf("AuthenticateAttestedClient: %v", err)
	}
	if got.Client.ID() != testClientID {
		t.Errorf("Client = %q, want %q", got.Client.ID(), testClientID)
	}
	if want := time.Unix(h.now.Add(time.Hour).Unix(), 0); !got.AttestationExpiresAt.Equal(want) {
		t.Errorf("AttestationExpiresAt = %v, want %v", got.AttestationExpiresAt, want)
	}
	events := h.audit.all()
	if len(events) != 1 || events[0].Type != server.AuditEventAuthenticateAttestedClient ||
		events[0].Outcome != server.AuditOutcomeSuccess || events[0].ClientID != testClientID {
		t.Errorf("audit events = %+v, want one AuditEventAuthenticateAttestedClient success for %q", events, testClientID)
	}
}

// TestAuthenticateAttestedClientX5CIssuerInCertificate covers the
// trust-list setup: an attester certificate chaining to a shared anchor
// and naming the client's attester.
func TestAuthenticateAttestedClientX5CIssuerInCertificate(t *testing.T) {
	root := newTestCert(t, "trust list CA", certOptions{isCA: true})
	trust := server.X5CAttesterChain{TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(root)}, IssuerBinding: server.AttesterIssuerInCertificate}
	for name, tc := range map[string]struct {
		san    string
		wantOK bool
	}{
		"certificate names the client's attester": {testAttesterIssuer, true},
		"certificate names another attester":      {"https://attester-b.example.com", false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, trust)
			leaf := newTestCert(t, "attester", certOptions{parent: &root, uris: []string{tc.san}})
			instanceKey := generateKey(t)
			_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
				ClientAttestations:    []string{createX5CAttestation(t, leaf.key, x5cOf(leaf), "", &instanceKey.PublicKey, h.now)},
				ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-x5c", h.now)},
			})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("AuthenticateAttestedClient: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

func TestAuthenticateAttestedClientRefusals(t *testing.T) {
	attesterKey, instanceKey, otherKey := generateKey(t), generateKey(t), generateKey(t)
	now := time.Now()
	attestation := createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, now, time.Hour)
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", now)

	cases := map[string]struct {
		tweak                func(*server.Config, *storage.RegisteredClientConfig)
		attestations, popHdr []string
	}{
		"feature disabled": {
			tweak: func(cfg *server.Config, _ *storage.RegisteredClientConfig) {
				cfg.AttestationBasedClientAuthentication = false
			},
			attestations: []string{attestation}, popHdr: []string{pop},
		},
		"client not registered for attestation": {
			tweak: func(_ *server.Config, c *storage.RegisteredClientConfig) {
				c.ClientAuthMethod, c.ClientAssertionAlgorithm = storage.ClientAuthMethodPrivateKeyJWT, fapi.ES256
				var noAlgorithm fapi.SignatureAlgorithm
				c.ExpectedAttesterIssuer, c.ClientAttestationAlgorithm = "", noAlgorithm
			},
			attestations: []string{attestation}, popHdr: []string{pop},
		},
		"attestation algorithm not permitted": {
			tweak: func(cfg *server.Config, _ *storage.RegisteredClientConfig) {
				cfg.Algorithms.ClientAttestation = server.AlgorithmSet{fapi.PS256}
			},
			attestations: []string{attestation}, popHdr: []string{pop},
		},
		"pop algorithm not permitted": {
			tweak: func(cfg *server.Config, _ *storage.RegisteredClientConfig) {
				cfg.Algorithms.ClientAttestationPoP = server.AlgorithmSet{fapi.PS256}
			},
			attestations: []string{attestation}, popHdr: []string{pop},
		},
		"unknown client": {
			attestations: []string{createAttestationHeader(t, attesterKey, "someone-else", &instanceKey.PublicKey, now, time.Hour)},
			popHdr:       []string{createAttestationPoPHeader(t, instanceKey, "someone-else", testIssuer, "jti-1", now)},
		},
		"untrusted attester": {
			attestations: []string{createAttestationHeader(t, otherKey, testClientID.String(), &instanceKey.PublicKey, now, time.Hour)},
			popHdr:       []string{pop},
		},
		"expired attestation": {
			attestations: []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, now.Add(-2*time.Hour), time.Hour)},
			popHdr:       []string{pop},
		},
		"pop signed by another key": {
			attestations: []string{attestation},
			popHdr:       []string{createAttestationPoPHeader(t, otherKey, testClientID.String(), testIssuer, "jti-1", now)},
		},
		"pop issued by another client": {
			attestations: []string{attestation},
			popHdr:       []string{createAttestationPoPHeader(t, instanceKey, "someone-else", testIssuer, "jti-1", now)},
		},
		"pop for another audience": {
			attestations: []string{attestation},
			popHdr:       []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), "https://other-issuer.example.com", "jti-1", now)},
		},
		"stale pop": {
			attestations: []string{attestation},
			popHdr:       []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", now.Add(-10*time.Minute))},
		},
		"no attestation headers":  {},
		"attestation without pop": {attestations: []string{attestation}},
		"pop without attestation": {popHdr: []string{pop}},
		"two attestations":        {attestations: []string{attestation, attestation}, popHdr: []string{pop}},
		"two pops":                {attestations: []string{attestation}, popHdr: []string{pop, pop}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newAttestationHarness(t, now, attesterKey, server.RegisteredAttesterKeys{}, tc.tweak)
			_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
				ClientAttestations: tc.attestations, ClientAttestationPoPs: tc.popHdr,
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q (err %v)", code, server.ErrorInvalidClient, err)
			}
			events := h.audit.all()
			if len(events) != 1 || events[0].Type != server.AuditEventAuthenticateAttestedClient || events[0].Outcome != server.AuditOutcomeFailure {
				t.Errorf("audit events = %+v, want one AuditEventAuthenticateAttestedClient failure", events)
			}
		})
	}
}

// TestAuthenticateAttestedClientSharesPoPReplay covers a PoP being
// usable once across AuthenticateAttestedClient and the server's own
// token endpoint, in either order.
func TestAuthenticateAttestedClientSharesPoPReplay(t *testing.T) {
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	authenticate := func(h harness, req server.AttestedClientAuthenticationRequest) error {
		_, err := h.server.AuthenticateAttestedClient(context.Background(), req)
		return err
	}
	tokenEndpoint := func(h harness, req server.AttestedClientAuthenticationRequest) error {
		_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
			HTTP:               server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
			ClientAttestations: req.ClientAttestations, ClientAttestationPoPs: req.ClientAttestationPoPs,
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}
	type use func(harness, server.AttestedClientAuthenticationRequest) error
	for name, order := range map[string][2]use{
		"twice here":                      {authenticate, authenticate},
		"token endpoint first, then here": {tokenEndpoint, authenticate},
		"here first, then token endpoint": {authenticate, tokenEndpoint},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttestationClientCredentials(t, attesterKey)
			req := attestedClientRequest(t, h, attesterKey, instanceKey, "same-jti")
			if err := order[0](h, req); err != nil {
				t.Fatalf("first use: %v", err)
			}
			if code := serverErrorCode(t, order[1](h, req)); code != server.ErrorInvalidClient {
				t.Fatalf("second use: error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

// TestAuthenticateAttestedClientWithoutHeaders covers a request with no
// attestation at all being told it needs client authentication, rather
// than that an attestation it never sent is malformed.
func TestAuthenticateAttestedClientWithoutHeaders(t *testing.T) {
	h := newHarnessWithAttestationClientCredentials(t, generateKey(t))
	_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{})
	var serr *server.Error
	if !errors.As(err, &serr) || serr.PublicDescription() != "client authentication is required" {
		t.Fatalf("AuthenticateAttestedClient(no headers) = %v, want invalid_client: client authentication is required", err)
	}
}
