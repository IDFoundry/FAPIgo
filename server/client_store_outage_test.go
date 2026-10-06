package server_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// clientLookupCases are the three ways a ClientRepository lookup can
// fail, and what each client-authenticating endpoint must answer: a
// store that couldn't answer (it said so, or the request's own context
// ended first) is the server's problem, 500 server_error; anything else
// is an unknown client.
func clientLookupCases() []struct {
	name     string
	storeErr error
	cancel   bool
	want     server.ErrorCode
	status   int
} {
	return []struct {
		name     string
		storeErr error
		cancel   bool
		want     server.ErrorCode
		status   int
	}{
		{"store unavailable", fmt.Errorf("db: %w", storage.ErrStoreUnavailable), false, server.ErrorServerError, 500},
		{"request cancelled", errors.New("lookup interrupted"), true, server.ErrorServerError, 500},
		{"unknown client", errors.New("no such client"), false, server.ErrorInvalidClient, 401},
	}
}

func lookupContext(t *testing.T, cancel bool) context.Context {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	if cancel {
		stop()
	} else {
		t.Cleanup(stop)
	}
	return ctx
}

func checkServerError(t *testing.T, err error, want server.ErrorCode, status int) {
	t.Helper()
	var srvErr *server.Error
	if !errors.As(err, &srvErr) {
		t.Fatalf("error = %v, want a *server.Error", err)
	}
	if srvErr.Code() != want || srvErr.HTTPStatus() != status {
		t.Fatalf("error = %s %d, want %s %d", srvErr.Code(), srvErr.HTTPStatus(), want, status)
	}
}

// TestClientStoreOutageAtAssertionAuthentication covers private_key_jwt
// client authentication, which PAR, the token endpoint, CIBA and
// revocation all share.
func TestClientStoreOutageAtAssertionAuthentication(t *testing.T) {
	for _, tc := range clientLookupCases() {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			assertion := h.clientAssertion(t)
			h.clients.err = tc.storeErr
			_, err := h.server.PushAuthorizationRequest(lookupContext(t, tc.cancel), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
			})
			checkServerError(t, err, tc.want, tc.status)
		})
	}
}

func TestClientStoreOutageAtCertificateAuthentication(t *testing.T) {
	for _, tc := range clientLookupCases() {
		t.Run(tc.name, func(t *testing.T) {
			h, cert := newHarnessWithClientAuthSelfSignedTLS(t)
			h.clients.err = tc.storeErr
			_, err := h.server.PushAuthorizationRequest(lookupContext(t, tc.cancel), server.PushAuthorizationRequest{
				HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
				PeerCertificate: cert,
			})
			checkServerError(t, err, tc.want, tc.status)
		})
	}
}

func TestClientStoreOutageAtAttestationAuthentication(t *testing.T) {
	for _, tc := range clientLookupCases() {
		t.Run(tc.name, func(t *testing.T) {
			attesterKey := generateKey(t)
			instanceKey := generateKey(t)
			dpopKey := generateKey(t)
			h := newHarnessWithAttestationClientCredentials(t, attesterKey)
			attestation := createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)
			pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", h.now)
			h.clients.err = tc.storeErr
			_, err := h.server.RequestClientCredentialsToken(lookupContext(t, tc.cancel), server.ClientCredentialsTokenRequest{
				HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
				ClientAttestations:    []string{attestation},
				ClientAttestationPoPs: []string{pop},
				DPoPProofs:            []string{createDPoPProof(t, dpopKey, h.now)},
			})
			checkServerError(t, err, tc.want, tc.status)
		})
	}
}

// TestClientStoreOutageAtBeginAuthorization: BeginAuthorization
// resolves the client again; an outage there is 500 server_error, not
// the unauthorized_client a client that's no longer registered gets.
func TestClientStoreOutageAtBeginAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name     string
		storeErr error
		cancel   bool
		want     server.ErrorCode
		status   int
	}{
		{"store unavailable", fmt.Errorf("db: %w", storage.ErrStoreUnavailable), false, server.ErrorServerError, 500},
		{"request cancelled", errors.New("lookup interrupted"), true, server.ErrorServerError, 500},
		{"no longer registered", errors.New("no such client"), false, server.ErrorUnauthorizedClient, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			pushed, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
			})
			if err != nil {
				t.Fatalf("PushAuthorizationRequest: %v", err)
			}
			h.clients.err = tc.storeErr
			action, err := h.server.BeginAuthorization(lookupContext(t, tc.cancel), server.BeginAuthorizationRequest{
				RequestURI: pushed.RequestURI.String(),
				ClientID:   testClientID,
			})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			local, ok := action.(server.LocalErrorResponse)
			if !ok {
				t.Fatalf("action = %T, want server.LocalErrorResponse", action)
			}
			checkServerError(t, local.Error, tc.want, tc.status)
		})
	}
}
