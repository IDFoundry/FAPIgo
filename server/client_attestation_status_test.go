package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// recordingStatusChecker is a ClientAttestationStatusChecker returning
// err, recording every attestation it is asked about. With scribble set
// it also changes the claims it's given, as a careless checker might.
type recordingStatusChecker struct {
	mu       sync.Mutex
	err      error
	scribble bool
	calls    []server.VerifiedClientAttestation
}

func (c *recordingStatusChecker) CheckClientAttestationStatus(_ context.Context, a server.VerifiedClientAttestation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	recorded := a
	recorded.Claims = make(map[string]json.RawMessage, len(a.Claims))
	for name, value := range a.Claims {
		recorded.Claims[name] = append(json.RawMessage(nil), value...)
	}
	c.calls = append(c.calls, recorded)
	if c.scribble {
		a.Claims["sub"] = json.RawMessage(`"someone-else"`)
		if status := a.Claims["status"]; len(status) > 0 {
			status[0] = 'X'
		}
	}
	return c.err
}

func (c *recordingStatusChecker) set(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *recordingStatusChecker) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func (c *recordingStatusChecker) last(t *testing.T) server.VerifiedClientAttestation {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.calls) == 0 {
		t.Fatal("the status checker was never called")
	}
	return c.calls[len(c.calls)-1]
}

// withAttestationStatus rebuilds h's server, over the same stores, with
// checker as Dependencies.ClientAttestationStatus.
func withAttestationStatus(t *testing.T, h harness, checker server.ClientAttestationStatusChecker) harness {
	t.Helper()
	h.deps.ClientAttestationStatus = checker
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	return h
}

// requireErrorStatus fails t unless err is a *server.Error with code and
// HTTP status.
func requireErrorStatus(t *testing.T, err error, code server.ErrorCode, status int) {
	t.Helper()
	var serverErr *server.Error
	if !errors.As(err, &serverErr) {
		t.Fatalf("err = %v, want %s (%d)", err, code, status)
	}
	if serverErr.Code() != code || serverErr.HTTPStatus() != status {
		t.Fatalf("err = %s (%d) %v, want %s (%d)", serverErr.Code(), serverErr.HTTPStatus(), err, code, status)
	}
}

// TestClientAttestationStatusAtEveryEndpoint covers the status checker's
// verdict at every endpoint an attestation authenticates at: revoked is
// invalid_client (401), undecided is server_error (500), and the request
// goes through again once the checker accepts.
func TestClientAttestationStatusAtEveryEndpoint(t *testing.T) {
	outcomes := map[string]struct {
		err    error
		code   server.ErrorCode
		status int
	}{
		"revoked":   {fmt.Errorf("status list says so: %w", server.ErrClientAttestationRevoked), server.ErrorInvalidClient, 401},
		"undecided": {errors.New("status list unreachable"), server.ErrorServerError, 500},
	}
	// Each endpoint's setup runs while the checker accepts; call is the
	// request the checker's verdict then decides.
	endpoints := map[string]func(i *attestedInstance) (call func() error){
		"PAR": func(i *attestedInstance) func() error {
			return func() error {
				attestations, pops := i.headers()
				_, err := i.h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
					HTTP: server.FormRequest{Parameters: []server.FormParameter{
						formParam("client_id", testClientID.String()),
						formParam("response_type", "code"),
						formParam("redirect_uri", testRedirectURI),
						formParam("scope", "openid accounts"),
						formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
						formParam("code_challenge_method", "S256"),
					}},
					ClientAttestations: attestations, ClientAttestationPoPs: pops,
				})
				return err
			}
		},
		"authorization code exchange": func(i *attestedInstance) func() error {
			code := i.attestedCode()
			return func() error { _, err := i.exchangeCode(code, testCodeVerifier); return err }
		},
		"refresh": func(i *attestedInstance) func() error {
			refreshToken := i.issueRefreshToken()
			return func() error { _, err := i.refresh(refreshToken); return err }
		},
		"revocation": func(i *attestedInstance) func() error {
			refreshToken := i.issueRefreshToken()
			return func() error {
				return i.revoke(formParam("token", refreshToken), formParam("token_type_hint", "refresh_token"))
			}
		},
		"client_credentials": func(i *attestedInstance) func() error {
			return func() error {
				attestations, pops := i.headers()
				_, err := i.h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
					HTTP:               server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
					ClientAttestations: attestations, ClientAttestationPoPs: pops,
					DPoPProofs: []string{createDPoPProof(i.t, generateKey(i.t), i.h.now)},
				})
				return err
			}
		},
		"AuthenticateAttestedClient": func(i *attestedInstance) func() error {
			return func() error {
				attestations, pops := i.headers()
				_, err := i.h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
					ClientAttestations: attestations, ClientAttestationPoPs: pops,
				})
				return err
			}
		},
	}
	for endpoint, setup := range endpoints {
		for outcome, want := range outcomes {
			t.Run(endpoint+"/"+outcome, func(t *testing.T) {
				attesterKey := generateKey(t)
				checker := &recordingStatusChecker{}
				h := withAttestationStatus(t, newRevocationHarness(t, attesterKey), checker)
				instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
				call := setup(instance)

				checker.set(want.err)
				before := checker.callCount()
				err := call()
				requireErrorStatus(t, err, want.code, want.status)
				if !errors.Is(err, want.err) {
					t.Errorf("err = %v, want it to wrap the checker's %v", err, want.err)
				}
				if checker.callCount() != before+1 {
					t.Errorf("checker called %d times for the request, want once", checker.callCount()-before)
				}

				checker.set(nil)
				if err := call(); err != nil {
					t.Fatalf("once the checker accepts: %v", err)
				}
			})
		}
	}
}

// TestClientAttestationStatusAtCIBA covers the checker at the CIBA
// backchannel authentication endpoint.
func TestClientAttestationStatusAtCIBA(t *testing.T) {
	attesterKey := generateKey(t)
	checker := &recordingStatusChecker{err: fmt.Errorf("withdrawn: %w", server.ErrClientAttestationRevoked)}
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
		cfg.AttestationBasedClientAuthentication = true
		cfg.Algorithms.ClientAttestation = server.AlgorithmSet{fapi.ES256}
		cfg.Algorithms.ClientAttestationPoP = server.AlgorithmSet{fapi.ES256}
		cfg.Limits.MaxClientAttestationLifetime = time.Hour
		cfg.Limits.MaxClientAttestationPoPAge = time.Minute
	}, func(deps *server.Dependencies) {
		client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                         testClientID,
			RedirectURIs:               []fapi.RegisteredRedirectURI{testRedirectURI},
			ClientAuthMethod:           storage.ClientAuthMethodAttestation,
			ExpectedAttesterIssuer:     testAttesterIssuer,
			ClientAttestationAlgorithm: fapi.ES256,
			AllowedScopes:              []string{"openid", "accounts"},
			BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		})
		if err != nil {
			t.Fatalf("NewRegisteredClient: %v", err)
		}
		deps.Clients = &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}}
		deps.ClientKeys = &fakeClientKeySource{keysByClient: registeredAttesterKeys(attesterKey)}
		deps.AttesterTrust = registeredAttesterTrust(fapi.ES256, &attesterKey.PublicKey)
		deps.ClientAttestationStatus = checker
	})
	h.key = attesterKey
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	begin := func() error {
		attestations, pops := instance.headers()
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("client_id", testClientID.String()),
				formParam("request", h.backchannelRequestObject(t, standardBackchannelParams(t))),
			}},
			ClientAttestations: attestations, ClientAttestationPoPs: pops,
		})
		if local, ok := action.(server.BackchannelAuthenticationLocalError); ok {
			return local.Error
		}
		return err
	}
	requireErrorStatus(t, begin(), server.ErrorInvalidClient, 401)
	checker.set(nil)
	if err := begin(); err != nil {
		t.Fatalf("BeginBackchannelAuthentication once the checker accepts: %v", err)
	}
}

// TestClientAttestationStatusAudited covers a refusal by the checker
// reaching the audit record with its error code.
func TestClientAttestationStatusAudited(t *testing.T) {
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	checker := &recordingStatusChecker{err: errors.New("unreachable")}
	h := withAttestationStatus(t, newHarnessWithAttestationClientCredentials(t, attesterKey), checker)
	_, err := h.server.AuthenticateAttestedClient(context.Background(), attestedClientRequest(t, h, attesterKey, instanceKey, "jti-audit"))
	requireErrorStatus(t, err, server.ErrorServerError, 500)
	events := h.audit.all()
	if len(events) != 1 || events[0].Outcome != server.AuditOutcomeFailure || !strings.Contains(events[0].Description, string(server.ErrorServerError)) {
		t.Fatalf("audit events = %+v, want one failure described %s", events, server.ErrorServerError)
	}
}

// TestClientAttestationStatusNotAskedBeforeVerification covers the
// checker being asked only about an attestation that verified with its
// PoP: never about one whose attestation or PoP fails, nor a replayed
// PoP.
func TestClientAttestationStatusNotAskedBeforeVerification(t *testing.T) {
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	checker := &recordingStatusChecker{}
	h := withAttestationStatus(t, newHarnessWithAttestationClientCredentials(t, attesterKey), checker)
	attestation := createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour)

	// A genuine request first, so the replay case has a PoP to replay.
	replayed := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-used", h.now)
	if _, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
		ClientAttestations: []string{attestation}, ClientAttestationPoPs: []string{replayed},
	}); err != nil {
		t.Fatalf("AuthenticateAttestedClient: %v", err)
	}
	asked := checker.callCount()

	for name, tc := range map[string]struct{ attestation, pop string }{
		"attestation signed by another key": {
			createAttestationHeader(t, generateKey(t), testClientID.String(), &instanceKey.PublicKey, h.now, time.Hour),
			createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-a", h.now),
		},
		"expired attestation": {
			createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, h.now.Add(-2*time.Hour), time.Hour),
			createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-b", h.now),
		},
		"PoP signed by another key": {
			attestation,
			createAttestationPoPHeader(t, generateKey(t), testClientID.String(), testIssuer, "jti-c", h.now),
		},
		"PoP for another audience": {
			attestation,
			createAttestationPoPHeader(t, instanceKey, testClientID.String(), "https://other.example.com", "jti-d", h.now),
		},
		"replayed PoP": {attestation, replayed},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
				ClientAttestations: []string{tc.attestation}, ClientAttestationPoPs: []string{tc.pop},
			})
			if err == nil {
				t.Fatal("AuthenticateAttestedClient succeeded")
			}
			if checker.callCount() != asked {
				t.Fatalf("checker asked about a request that failed verification (%v)", err)
			}
		})
	}
}

// TestClientAttestationStatusReceivesVerifiedAttestation covers what the
// checker is given, under RegisteredAttesterKeys: every claim, including
// a status claim this package doesn't read, the attestation's times, the
// instance key's thumbprint and the attester key, with no certificates.
// A checker changing the claims doesn't change what the next call gets.
func TestClientAttestationStatusReceivesVerifiedAttestation(t *testing.T) {
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	checker := &recordingStatusChecker{scribble: true}
	h := withAttestationStatus(t, newHarnessWithAttestationClientCredentials(t, attesterKey), checker)
	status := `{"status_list":{"idx":42,"uri":"https://attester.example.com/statuslists/1"}}`
	attestation := attestationWithStatus(t, attesterKey, &instanceKey.PublicKey, h.now, status)

	for n := range 2 {
		pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, fmt.Sprintf("jti-%d", n), h.now)
		if _, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
			ClientAttestations: []string{attestation}, ClientAttestationPoPs: []string{pop},
		}); err != nil {
			t.Fatalf("AuthenticateAttestedClient %d: %v", n, err)
		}
		got := checker.last(t)
		requireStatusClaims(t, got, status)
		requireStatusKeysAndTimes(t, got, h.now, instanceKey, attesterKey)
	}
}

// requireStatusClaims checks the client and claims
// TestClientAttestationStatusReceivesVerifiedAttestation's checker got.
func requireStatusClaims(t *testing.T, got server.VerifiedClientAttestation, status string) {
	t.Helper()
	if got.Client.ID() != testClientID {
		t.Errorf("Client = %q, want %q", got.Client.ID(), testClientID)
	}
	requireClaim(t, got.Claims, "status", status)
	requireClaim(t, got.Claims, "iss", `"`+testAttesterIssuer+`"`)
	requireClaim(t, got.Claims, "sub", `"`+testClientID.String()+`"`)
	if _, ok := got.Claims["cnf"]; !ok {
		t.Errorf("Claims lacks cnf")
	}
}

// requireStatusKeysAndTimes checks the times and keys
// TestClientAttestationStatusReceivesVerifiedAttestation's checker got.
func requireStatusKeysAndTimes(t *testing.T, got server.VerifiedClientAttestation, now time.Time, instanceKey, attesterKey *ecdsa.PrivateKey) {
	t.Helper()
	if want := time.Unix(now.Unix(), 0); !got.IssuedAt.Equal(want) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, want)
	}
	if want := time.Unix(now.Add(time.Hour).Unix(), 0); !got.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want)
	}
	if want := instanceThumbprint(t, instanceKey); got.InstanceKey != want {
		t.Errorf("InstanceKey = %q, want %q", got.InstanceKey, want)
	}
	if signer, ok := got.SignerKey.(*ecdsa.PublicKey); !ok || !signer.Equal(&attesterKey.PublicKey) {
		t.Errorf("SignerKey = %v, want the attester's key", got.SignerKey)
	}
	if got.SignerCertificates != nil {
		t.Errorf("SignerCertificates = %v, want nil under RegisteredAttesterKeys", got.SignerCertificates)
	}
}

// TestClientAttestationStatusReceivesX5CChain covers what the checker is
// given under X5CAttesterChain: the leaf's key, and the verified chain
// from the leaf to the trust anchor.
func TestClientAttestationStatusReceivesX5CChain(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	intermediate := newTestCert(t, "intermediate", certOptions{parent: &root, isCA: true})
	leaf := newTestCert(t, "attester", certOptions{parent: &intermediate})
	checker := &recordingStatusChecker{}
	h := withAttestationStatus(t, newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
		TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
		IssuerBinding: server.AttesterIssuerByTrustAnchors,
		Revocation:    server.NoClientCertificateRevocationCheck{},
	}), checker)
	instanceKey := generateKey(t)
	attestation := createX5CAttestation(t, leaf.key, x5cOf(leaf, intermediate), "", &instanceKey.PublicKey, h.now)
	if err := requestWithAttestation(t, h, attestation, instanceKey); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	got := checker.last(t)
	if signer, ok := got.SignerKey.(*ecdsa.PublicKey); !ok || !signer.Equal(leaf.cert.PublicKey) {
		t.Errorf("SignerKey = %v, want the leaf certificate's key", got.SignerKey)
	}
	requireChain(t, got.SignerCertificates, leaf, intermediate, root)
}

// TestX5CAttesterChainRevocation covers X5CAttesterChain.Revocation:
// asked with the verified chain, leaf to anchor, at the server's Clock
// time, once the attestation and PoP have verified; an error wrapping
// ErrCertificateRevoked refuses the client with invalid_client, and any
// other error, a check that couldn't decide, with server_error.
func TestX5CAttesterChainRevocation(t *testing.T) {
	serverNow := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	root := newTestCert(t, "root", certOptions{isCA: true, keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	intermediate := newTestCert(t, "intermediate", certOptions{parent: &root, isCA: true, keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	leaf := newTestCert(t, "attester", certOptions{parent: &intermediate})
	other := newTestCert(t, "other attester", certOptions{parent: &intermediate})
	x5c := x5cOf(leaf, intermediate)

	run := func(t *testing.T, revocation server.ClientCertificateRevocation) error {
		t.Helper()
		h := newHarnessWithAttesterTrustAt(t, serverNow, nil, server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
			IssuerBinding: server.AttesterIssuerByTrustAnchors,
			Revocation:    revocation,
		})
		instanceKey := generateKey(t)
		return requestWithAttestation(t, h, createX5CAttestation(t, leaf.key, x5c, "", &instanceKey.PublicKey, h.now), instanceKey)
	}

	t.Run("checked with the chain at the server clock", func(t *testing.T) {
		recorder := &recordingRevocation{}
		if err := run(t, recorder); err != nil {
			t.Fatalf("RequestClientCredentialsToken: %v", err)
		}
		if len(recorder.checks) != 1 {
			t.Fatalf("revocation checked %d times, want once", len(recorder.checks))
		}
		if !recorder.checks[0].Now.Equal(serverNow) {
			t.Errorf("Now = %v, want the server clock's %v", recorder.checks[0].Now, serverNow)
		}
		requireChain(t, recorder.checks[0].Chain, leaf, intermediate, root)
	})
	t.Run("a revoked certificate refuses the client", func(t *testing.T) {
		err := run(t, &recordingRevocation{err: fmt.Errorf("%w: OCSP says revoked", server.ErrCertificateRevoked)})
		requireErrorStatus(t, err, server.ErrorInvalidClient, 401)
	})
	t.Run("an undecided check is a server error", func(t *testing.T) {
		requireErrorStatus(t, run(t, &recordingRevocation{err: errors.New("OCSP responder unreachable")}), server.ErrorServerError, 500)
	})
	t.Run("CRLs, lists error", func(t *testing.T) {
		failing := server.ClientCertificateCRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
			return nil, errors.New("CRL cache empty")
		}}
		requireErrorStatus(t, run(t, failing), server.ErrorServerError, 500)
	})
	thisUpdate, nextUpdate := serverNow.Add(-time.Hour), serverNow.Add(time.Hour)
	rootCRL := testCertCRL(t, root, thisUpdate, nextUpdate)
	for name, tc := range map[string]struct {
		lists  []*x509.RevocationList
		code   server.ErrorCode // "" accepts
		status int
	}{
		"nothing revoked":            {[]*x509.RevocationList{rootCRL, testCertCRL(t, intermediate, thisUpdate, nextUpdate, other)}, "", 0},
		"leaf revoked":               {[]*x509.RevocationList{rootCRL, testCertCRL(t, intermediate, thisUpdate, nextUpdate, leaf)}, server.ErrorInvalidClient, 401},
		"intermediate revoked":       {[]*x509.RevocationList{testCertCRL(t, root, thisUpdate, nextUpdate, intermediate), testCertCRL(t, intermediate, thisUpdate, nextUpdate)}, server.ErrorInvalidClient, 401},
		"intermediate's CRL missing": {[]*x509.RevocationList{rootCRL}, server.ErrorServerError, 500},
		"intermediate's CRL expired": {[]*x509.RevocationList{rootCRL, testCertCRL(t, intermediate, serverNow.Add(-2*time.Hour), serverNow.Add(-time.Hour))}, server.ErrorServerError, 500},
		"no CRLs at all":             {nil, server.ErrorServerError, 500},
	} {
		t.Run("CRLs, "+name, func(t *testing.T) {
			err := run(t, staticCRLs(tc.lists...))
			if tc.code == "" {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			requireErrorStatus(t, err, tc.code, tc.status)
		})
	}
}

// TestX5CAttesterChainRevocationNotAskedBeforePoP covers the attester
// certificate's revocation being checked only once the PoP verifies.
func TestX5CAttesterChainRevocationNotAskedBeforePoP(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	leaf := newTestCert(t, "attester", certOptions{parent: &root})
	recorder := &recordingRevocation{}
	h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
		TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
		IssuerBinding: server.AttesterIssuerByTrustAnchors,
		Revocation:    recorder,
	})
	instanceKey := generateKey(t)
	attestation := createX5CAttestation(t, leaf.key, x5cOf(leaf), "", &instanceKey.PublicKey, h.now)
	if err := requestWithAttestation(t, h, attestation, generateKey(t)); err == nil {
		t.Fatal("a PoP signed by another key was accepted")
	}
	if len(recorder.checks) != 0 {
		t.Fatalf("revocation checked %d times before the PoP verified", len(recorder.checks))
	}
}

// TestX5CAttesterChainRevocationBoundAnchorChain covers, under
// AttesterIssuerBoundToAnchor, the chain revocation and the status
// checker are given being the one ending at the anchor bound to the
// client's attester.
func TestX5CAttesterChainRevocationBoundAnchorChain(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	leaf := newTestCert(t, "attester", certOptions{parent: &root, uris: []string{testAttesterIssuer}})
	recorder := &recordingRevocation{}
	checker := &recordingStatusChecker{}
	h := withAttestationStatus(t, newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
		Anchors:       server.StaticAttesterAnchors{{Certificate: root.cert, Issuers: []string{testAttesterIssuer}}},
		IssuerBinding: server.AttesterIssuerBoundToAnchor,
		Revocation:    recorder,
	}), checker)
	instanceKey := generateKey(t)
	if err := requestWithAttestation(t, h, createX5CAttestation(t, leaf.key, x5cOf(leaf), "", &instanceKey.PublicKey, h.now), instanceKey); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if len(recorder.checks) != 1 {
		t.Fatalf("revocation checked %d times, want once", len(recorder.checks))
	}
	requireChain(t, recorder.checks[0].Chain, leaf, root)
	requireChain(t, checker.last(t).SignerCertificates, leaf, root)
}

// TestNewClientAttestationStatusRequirements covers New's checks of
// Dependencies.ClientAttestationStatus and X5CAttesterChain.Revocation.
func TestNewClientAttestationStatusRequirements(t *testing.T) {
	x5c := func(revocation server.ClientCertificateRevocation) server.X5CAttesterChain {
		return server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()},
			IssuerBinding: server.AttesterIssuerInCertificate,
			Revocation:    revocation,
		}
	}
	for name, tc := range map[string]struct {
		production bool
		trust      server.AttesterTrust
		checker    server.ClientAttestationStatusChecker
		want       string // "" accepts
	}{
		"production refuses no checker":           {true, nil, nil, "client_attestation_status is required under AssuranceProduction"},
		"production accepts the explicit decline": {true, nil, server.NoClientAttestationStatusCheck{}, ""},
		"production accepts a checker":            {true, nil, &recordingStatusChecker{}, ""},
		"development accepts no checker":          {false, nil, nil, ""},
		"nil decline pointer":                     {false, nil, (*server.NoClientAttestationStatusCheck)(nil), "nil *NoClientAttestationStatusCheck"},
		"decline by pointer":                      {false, nil, &server.NoClientAttestationStatusCheck{}, ""},
		"x5c chain without revocation":            {false, x5c(nil), nil, "X5CAttesterChain.Revocation is required"},
		"x5c chain declining revocation":          {false, x5c(server.NoClientCertificateRevocationCheck{}), nil, ""},
		"x5c chain with CRLs":                     {false, x5c(staticCRLs()), nil, ""},
		"x5c chain with CRLs lacking lists":       {false, x5c(server.ClientCertificateCRLs{}), nil, "X5CAttesterChain.Revocation"},
		"x5c chain by pointer without revocation": {false, &server.X5CAttesterChain{TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}, IssuerBinding: server.AttesterIssuerInCertificate}, nil, "X5CAttesterChain.Revocation is required"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validAttestationConfig(t)
			deps := validDependencies()
			if tc.production {
				asProduction(&cfg)
				cfg.Deployment = server.DeploymentSingleInstance
				deps.Audit = &fakeAuditSink{}
			}
			if tc.trust != nil {
				deps.AttesterTrust = tc.trust
			}
			deps.ClientAttestationStatus = tc.checker
			_, err := server.New(cfg, deps)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	t.Run("not required with attestation disabled", func(t *testing.T) {
		if err := productionNew(t, func(*server.Dependencies) {}); err != nil {
			t.Fatalf("New(production, attestation disabled): %v", err)
		}
	})
}

// TestNoClientAttestationStatusCheckAcceptsEverything covers the
// explicit decline.
func TestNoClientAttestationStatusCheckAcceptsEverything(t *testing.T) {
	if err := (server.NoClientAttestationStatusCheck{}).CheckClientAttestationStatus(context.Background(), server.VerifiedClientAttestation{}); err != nil {
		t.Fatalf("CheckClientAttestationStatus = %v, want nil", err)
	}
}

// attestationWithStatus is createAttestationHeader with a status claim.
func attestationWithStatus(t *testing.T, attesterKey *ecdsa.PrivateKey, instancePub *ecdsa.PublicKey, now time.Time, status string) string {
	t.Helper()
	jwk, err := jose.NewJWK(instancePub, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss":    testAttesterIssuer,
		"sub":    testClientID.String(),
		"iat":    now.Unix(),
		"exp":    now.Add(time.Hour).Unix(),
		"cnf":    map[string]any{"jwk": json.RawMessage(jwkJSON)},
		"status": json.RawMessage(status),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(attesterKey, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.TypHeader}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

func requireClaim(t *testing.T, claims map[string]json.RawMessage, name, want string) {
	t.Helper()
	if got := string(claims[name]); got != want {
		t.Errorf("Claims[%q] = %s, want %s", name, got, want)
	}
}

// instanceThumbprint is the RFC 7638 thumbprint of key's public key.
func instanceThumbprint(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return thumbprint.String()
}

// requireChain fails t unless chain is exactly want's certificates, in
// order.
func requireChain(t *testing.T, chain []*x509.Certificate, want ...testCert) {
	t.Helper()
	if len(chain) != len(want) {
		t.Fatalf("chain has %d certificates, want %d", len(chain), len(want))
	}
	for i, c := range want {
		if !chain[i].Equal(c.cert) {
			t.Errorf("chain[%d] = %s, want %s", i, chain[i].Subject, c.cert.Subject)
		}
	}
}

// testCertCRL is a CRL issuer signs, valid over [thisUpdate, nextUpdate],
// listing revoked.
func testCertCRL(t *testing.T, issuer testCert, thisUpdate, nextUpdate time.Time, revoked ...testCert) *x509.RevocationList {
	t.Helper()
	template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate}
	for _, c := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber: c.cert.SerialNumber, RevocationTime: thisUpdate,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, issuer.cert, issuer.key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	return list
}
