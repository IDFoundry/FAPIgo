package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// draft12Attestation signs a Client Attestation for testClientID in
// draft-12's shape — sub, iat, exp and cnf, and no iss (draft-12 §4) —
// with signer, carrying x5c in its header when non-nil.
func draft12Attestation(t *testing.T, signer crypto.Signer, x5c json.RawMessage, instancePub *ecdsa.PublicKey, now time.Time, lifetime time.Duration) string {
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
		"sub": testClientID.String(),
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(jwkJSON)},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.TypHeader, X5C: x5c}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// draft12PoP signs a Client Attestation PoP in draft-12's shape — aud,
// jti and iat, and no iss (draft-12 §5.1) — plus any extra claims.
func draft12PoP(t *testing.T, instanceKey *ecdsa.PrivateKey, aud any, now time.Time, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"aud": aud, "jti": "jti-" + rand.Text(), "iat": now.Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(instanceKey, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.PoPTypHeader}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// attestedClientCredentials runs a client_credentials request
// authenticated by attestation and pop, with any extra form parameters.
func attestedClientCredentials(t *testing.T, h harness, attestation, pop string, extra ...server.FormParameter) error {
	t.Helper()
	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: append(attestationClientCredentialsFormParams("accounts"), extra...)},
		ClientAttestations:    []string{attestation},
		ClientAttestationPoPs: []string{pop},
		DPoPProofs:            []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	return err
}

// TestAttestationDraft12ShapesAuthenticate: a client following draft-12
// — no iss in either JWT, aud as a string or a one-element array — is
// authenticated, as one following draft-07 is.
func TestAttestationDraft12ShapesAuthenticate(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	for name, tc := range map[string]struct {
		attestation func(instance *ecdsa.PrivateKey) string
		pop         func(instance *ecdsa.PrivateKey) string
	}{
		"draft-12 attestation and PoP": {
			func(i *ecdsa.PrivateKey) string {
				return draft12Attestation(t, attesterKey, nil, &i.PublicKey, h.now, time.Hour)
			},
			func(i *ecdsa.PrivateKey) string { return draft12PoP(t, i, testIssuer, h.now, nil) },
		},
		"draft-12 PoP with aud as an array": {
			func(i *ecdsa.PrivateKey) string {
				return draft12Attestation(t, attesterKey, nil, &i.PublicKey, h.now, time.Hour)
			},
			func(i *ecdsa.PrivateKey) string { return draft12PoP(t, i, []string{testIssuer}, h.now, nil) },
		},
		"draft-07 attestation, draft-12 PoP": {
			func(i *ecdsa.PrivateKey) string {
				return createAttestationHeader(t, attesterKey, testClientID.String(), &i.PublicKey, h.now, time.Hour)
			},
			func(i *ecdsa.PrivateKey) string { return draft12PoP(t, i, testIssuer, h.now, nil) },
		},
		"draft-12 attestation, draft-07 PoP": {
			func(i *ecdsa.PrivateKey) string {
				return draft12Attestation(t, attesterKey, nil, &i.PublicKey, h.now, time.Hour)
			},
			func(i *ecdsa.PrivateKey) string {
				return createAttestationPoPHeader(t, i, testClientID.String(), testIssuer, "jti-"+rand.Text(), h.now)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			instance := generateKey(t)
			if err := attestedClientCredentials(t, h, tc.attestation(instance), tc.pop(instance)); err != nil {
				t.Fatalf("RequestClientCredentialsToken: %v", err)
			}
		})
	}
}

// TestAttestationIssStillCheckedWhenPresent: an iss, though no longer
// required, must still name the client's attester (attestation) or the
// client (PoP) when it's there.
func TestAttestationIssStillCheckedWhenPresent(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	instance := generateKey(t)
	wrongIss := signAttestationClaims(t, attesterKey, &instance.PublicKey, h.now, map[string]any{"iss": "https://attester-b.example.com"})
	if code := serverErrorCode(t, attestedClientCredentials(t, h, wrongIss, draft12PoP(t, instance, testIssuer, h.now, nil))); code != server.ErrorInvalidClient {
		t.Errorf("attestation naming another attester: code %q, want invalid_client", code)
	}
	attestation := draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now, time.Hour)
	popOtherClient := draft12PoP(t, instance, testIssuer, h.now, map[string]any{"iss": "someone-else"})
	if code := serverErrorCode(t, attestedClientCredentials(t, h, attestation, popOtherClient)); code != server.ErrorInvalidClient {
		t.Errorf("PoP naming another client: code %q, want invalid_client", code)
	}
}

// signAttestationClaims is draft12Attestation with extra claims added.
func signAttestationClaims(t *testing.T, signer crypto.Signer, instancePub *ecdsa.PublicKey, now time.Time, extra map[string]any) string {
	t.Helper()
	jwk, err := jose.NewJWK(instancePub, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	claims := map[string]any{
		"sub": testClientID.String(), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(jwkJSON)},
	}
	for k, v := range extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.TypHeader}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// TestAttestationWithoutIssCannotImpersonateAnotherAttester: dropping iss
// (draft-12) must not reopen the cross-attester impersonation #393
// closed. The attester is established by the key that verifies the
// attestation — resolved from the client's registered attester, or
// bound to it through the signing certificate — never by iss, so an
// attestation from another attester fails without iss exactly as it
// does with one.
func TestAttestationWithoutIssCannotImpersonateAnotherAttester(t *testing.T) {
	t.Run("registered attester keys", func(t *testing.T) {
		clientsAttester, otherAttester := generateKey(t), generateKey(t)
		h := newHarnessWithAttestationClientCredentials(t, clientsAttester)
		instance := generateKey(t)
		forged := draft12Attestation(t, otherAttester, nil, &instance.PublicKey, h.now, time.Hour)
		if code := serverErrorCode(t, attestedClientCredentials(t, h, forged, draft12PoP(t, instance, testIssuer, h.now, nil))); code != server.ErrorInvalidClient {
			t.Fatalf("another attester's attestation without iss: code %q, want invalid_client", code)
		}
	})

	sharedRoot := newTestCert(t, "trust list CA", certOptions{isCA: true})
	rootA := newTestCert(t, "attester A CA", certOptions{isCA: true})
	rootB := newTestCert(t, "attester B CA", certOptions{isCA: true})
	for name, tc := range map[string]struct {
		trust  server.X5CAttesterChain
		leaf   testCert
		wantOK bool
	}{
		"issuer in certificate: the client's attester": {
			server.X5CAttesterChain{TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(sharedRoot)}, IssuerBinding: server.AttesterIssuerInCertificate},
			newTestCert(t, "client's attester", certOptions{parent: &sharedRoot, uris: []string{testAttesterIssuer}}), true,
		},
		"issuer in certificate: another attester under the same anchor": {
			server.X5CAttesterChain{TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(sharedRoot)}, IssuerBinding: server.AttesterIssuerInCertificate},
			newTestCert(t, "attester B", certOptions{parent: &sharedRoot, uris: []string{"https://attester-b.example.com"}}), false,
		},
		"bound to anchor: another attester's CA naming the client's attester": {
			boundChain(server.StaticAttesterAnchors{
				{Certificate: rootA.cert, Issuers: []string{otherAttesterIssuer}},
				{Certificate: rootB.cert, Issuers: []string{testAttesterIssuer}},
			}),
			newTestCert(t, "A posing as B", certOptions{parent: &rootA, uris: []string{testAttesterIssuer}}), false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, tc.trust)
			instance := generateKey(t)
			attestation := draft12Attestation(t, tc.leaf.key, x5cOf(tc.leaf), &instance.PublicKey, h.now, time.Hour)
			err := attestedClientCredentials(t, h, attestation, draft12PoP(t, instance, testIssuer, h.now, nil))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("code %q (%v), want invalid_client", code, err)
			}
		})
	}
}

// TestAttestationClientIDParameterMustMatch: a client_id parameter beside
// a Client Attestation must name the attestation's sub (draft-12 §7.1
// rule 7, §7.5), at every endpoint a client authenticates at, as a
// client_id beside a client_assertion must.
func TestAttestationClientIDParameterMustMatch(t *testing.T) {
	attesterKey := generateKey(t)
	t.Run("token endpoint", func(t *testing.T) {
		h := newHarnessWithAttestationClientCredentials(t, attesterKey)
		instance := generateKey(t)
		send := func(clientID string) error {
			attestation := draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now, time.Hour)
			return attestedClientCredentials(t, h, attestation, draft12PoP(t, instance, testIssuer, h.now, nil), formParam("client_id", clientID))
		}
		if code := serverErrorCode(t, send("some-other-client")); code != server.ErrorInvalidClient {
			t.Errorf("mismatched client_id: code %q, want invalid_client", code)
		}
		if err := send(testClientID.String()); err != nil {
			t.Errorf("matching client_id: %v", err)
		}
	})
	t.Run("PAR", func(t *testing.T) {
		h := newInstanceBindingHarness(t, attesterKey)
		instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
		attestations, pops := instance.headers()
		_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("client_id", "some-other-client"),
				formParam("response_type", "code"),
				formParam("redirect_uri", testRedirectURI),
				formParam("scope", "openid accounts"),
				formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
				formParam("code_challenge_method", "S256"),
			}},
			ClientAttestations: attestations, ClientAttestationPoPs: pops,
		})
		if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
			t.Errorf("PAR with mismatched client_id: code %q, want invalid_client", code)
		}
	})
	t.Run("revocation", func(t *testing.T) {
		h := newRevocationHarness(t, attesterKey)
		instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
		attestations, pops := instance.headers()
		_, err := h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
			HTTP:               server.FormRequest{Parameters: []server.FormParameter{formParam("client_id", "some-other-client"), formParam("token", "anything")}},
			ClientAttestations: attestations, ClientAttestationPoPs: pops,
		})
		if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
			t.Errorf("revocation with mismatched client_id: code %q, want invalid_client", code)
		}
	})
	t.Run("AuthenticateAttestedClient", func(t *testing.T) {
		h := newHarnessWithAttestationClientCredentials(t, attesterKey)
		instance := generateKey(t)
		authenticate := func(clientID string) error {
			_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
				ClientAttestations:    []string{draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now, time.Hour)},
				ClientAttestationPoPs: []string{draft12PoP(t, instance, testIssuer, h.now, nil)},
				ClientID:              clientID,
			})
			return err
		}
		if code := serverErrorCode(t, authenticate("some-other-client")); code != server.ErrorInvalidClient {
			t.Errorf("mismatched ClientID: code %q, want invalid_client", code)
		}
		for _, clientID := range []string{testClientID.String(), ""} {
			if err := authenticate(clientID); err != nil {
				t.Errorf("ClientID %q: %v", clientID, err)
			}
		}
	})
}

// TestExpiredAttestationAsksForAFreshOne: an attestation whose signature
// verifies but that has expired is use_fresh_attestation with HTTP 400
// (draft-12 §7.4), so the client knows to get a new one rather than
// treating itself as unknown. Within the clock skew it's still accepted.
func TestExpiredAttestationAsksForAFreshOne(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	instance := generateKey(t)
	expired := draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now.Add(-2*time.Hour), time.Hour)
	err := attestedClientCredentials(t, h, expired, draft12PoP(t, instance, testIssuer, h.now, nil))
	var srvErr *server.Error
	if !errors.As(err, &srvErr) || srvErr.Code() != server.ErrorUseFreshAttestation || srvErr.HTTPStatus() != 400 {
		t.Fatalf("expired attestation: err = %v, want use_fresh_attestation (400)", err)
	}
	withinSkew := draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now.Add(-time.Hour-h.cfg.Limits.MaxClockSkew+time.Second), time.Hour)
	if err := attestedClientCredentials(t, h, withinSkew, draft12PoP(t, instance, testIssuer, h.now, nil)); err != nil {
		t.Fatalf("attestation expired within the clock skew: %v", err)
	}
	// An expired attestation from an attester the client doesn't trust
	// is not asked to be refreshed: its signature never verified.
	untrusted := draft12Attestation(t, generateKey(t), nil, &instance.PublicKey, h.now.Add(-2*time.Hour), time.Hour)
	if code := serverErrorCode(t, attestedClientCredentials(t, h, untrusted, draft12PoP(t, instance, testIssuer, h.now, nil))); code != server.ErrorInvalidClient {
		t.Fatalf("expired attestation from an untrusted attester: code %q, want invalid_client", code)
	}
}

// TestAttestationPoPTimeChecks: a PoP's exp, when it has one, is held to
// (RFC 7519 §4.1.4), and an attestation issued in the future is refused.
func TestAttestationPoPTimeChecks(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	skew := h.cfg.Limits.MaxClockSkew
	for name, tc := range map[string]struct {
		attestation func(instance *ecdsa.PrivateKey) string
		popExtra    map[string]any
		wantOK      bool
	}{
		"PoP exp ahead": {nil, map[string]any{"exp": h.now.Add(time.Minute).Unix()}, true},
		"PoP exp past":  {nil, map[string]any{"exp": h.now.Add(-skew - time.Second).Unix()}, false},
		"attestation issued in the future": {func(i *ecdsa.PrivateKey) string {
			return signAttestationClaims(t, attesterKey, &i.PublicKey, h.now, map[string]any{"iat": h.now.Add(skew + time.Minute).Unix()})
		}, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			instance := generateKey(t)
			attestation := draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now, time.Hour)
			if tc.attestation != nil {
				attestation = tc.attestation(instance)
			}
			err := attestedClientCredentials(t, h, attestation, draft12PoP(t, instance, testIssuer, h.now, tc.popExtra))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("code %q (%v), want invalid_client", code, err)
			}
		})
	}
}

// TestAttestationPoPReplayScopedToInstance: one installation can't use up
// a PoP jti another installation of the same client will send, while
// the same installation repeating a jti is still refused.
func TestAttestationPoPReplayScopedToInstance(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	send := func(instance *ecdsa.PrivateKey) error {
		attestation := draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now, time.Hour)
		return attestedClientCredentials(t, h, attestation, draft12PoP(t, instance, testIssuer, h.now, map[string]any{"jti": "victims-next-jti"}))
	}
	attacker, victim := generateKey(t), generateKey(t)
	if err := send(attacker); err != nil {
		t.Fatalf("attacker installation: %v", err)
	}
	if err := send(victim); err != nil {
		t.Fatalf("victim installation, same jti: %v", err)
	}
	if code := serverErrorCode(t, send(attacker)); code != server.ErrorInvalidClient {
		t.Fatalf("attacker repeating its jti: code %q, want invalid_client", code)
	}
}

// newMixedMethodHarness registers testClientID for both private_key_jwt
// (a backend holding backendKey) and Client Attestation (app
// installations attested by attesterKey).
func newMixedMethodHarness(t *testing.T, attesterKey, backendKey *ecdsa.PrivateKey) harness {
	t.Helper()
	revocation, err := fapi.ParseEndpointURL(testRevocationEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	h := newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
		cfg.Endpoints.Revocation = revocation
		c.ClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodAttestation, storage.ClientAuthMethodPrivateKeyJWT}
		c.ClientAssertionAlgorithm = fapi.ES256
		c.AllowedScopes = []string{"openid", "accounts", "offline_access"}
	})
	deps := h.deps
	deps.ClientKeys = &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
		testClientID: {{Algorithm: fapi.ES256, PublicKey: &backendKey.PublicKey}},
	}}
	srv, newErr := server.New(h.cfg, deps)
	if newErr != nil {
		t.Fatalf("server.New: %v", newErr)
	}
	h.server, h.deps = srv, deps
	return h
}

func backendAssertion(t *testing.T, key *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	a, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: key, Algorithm: fapi.ES256, ClientID: testClientID.String(), Audience: testIssuer,
		Now: now, Lifetime: 30 * time.Second, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return a
}

// TestRefreshTokenFromAnotherAuthMethodRefusedToInstance: a client
// registered for both private_key_jwt and Client Attestation gets
// refresh tokens without an instance key when it authenticates with its
// key. An attested installation must not redeem or revoke one — the
// backend's refresh token, leaked, would otherwise work for any genuine
// installation — while the backend itself still can.
func TestRefreshTokenFromAnotherAuthMethodRefusedToInstance(t *testing.T) {
	ctx := context.Background()
	attesterKey, backendKey := generateKey(t), generateKey(t)
	h := newMixedMethodHarness(t, attesterKey, backendKey)

	push, err := h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("client_assertion", backendAssertion(t, backendKey, h.now)),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
			formParam("code_challenge_method", "S256"),
		}},
	})
	if err != nil {
		t.Fatalf("PAR: %v", err)
	}
	action, err := h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	subjectID, _ := server.NewSubjectID("user-1")
	subject, _ := server.NewAuthenticatedSubject(subjectID)
	authCtx, _ := server.NewAuthenticationContext(h.now, "", nil)
	completed, err := h.server.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: action.(server.InteractionRequired).Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	destination := completed.(server.AuthorizationRedirect).Destination().URL()
	tokens, err := h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("client_assertion", backendAssertion(t, backendKey, h.now)),
			formParam("grant_type", "authorization_code"),
			formParam("code", destination.Query().Get("code")),
			formParam("redirect_uri", testRedirectURI),
			formParam("code_verifier", testCodeVerifier),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	refreshToken := tokens.RefreshToken.Reveal()

	installation := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	if code := serverErrorCode(t, firstErr(installation.refresh(refreshToken))); code != server.ErrorInvalidGrant {
		t.Fatalf("installation refreshing the backend's token: code %q, want invalid_grant", code)
	}
	result, err := installation.revokeResult(formParam("token", refreshToken))
	if err != nil || result.Revoked {
		t.Fatalf("installation revoking the backend's token = (%+v, %v), want not revoked", result, err)
	}

	if _, err := h.server.RefreshAccessToken(ctx, server.RefreshTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("client_assertion", backendAssertion(t, backendKey, h.now)),
			formParam("grant_type", "refresh_token"),
			formParam("refresh_token", refreshToken),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	}); err != nil {
		t.Fatalf("backend refreshing its own token: %v", err)
	}
}

// firstErr returns the error of a (result, error) pair.
func firstErr[T any](_ T, err error) error { return err }

// TestExtensionGrantClientIDMustMatchAttestation: an embedder's grant
// read with TokenEndpointRequestFromHTTP passes its client_id parameter
// on through AttestedClientAuthentication, so AuthenticateAttestedClient
// refuses one naming another client than the attestation does.
func TestExtensionGrantClientIDMustMatchAttestation(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	for clientID, wantOK := range map[string]bool{
		"":                    true,
		testClientID.String(): true,
		"some-other-client":   false,
	} {
		t.Run("client_id="+clientID, func(t *testing.T) {
			instance := generateKey(t)
			header := dpopHeader(dpopProofAt(t, generateKey(t), testTokenEndpoint, "", h.now))
			header.Set("OAuth-Client-Attestation", draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now, time.Hour))
			header.Set("OAuth-Client-Attestation-PoP", draft12PoP(t, instance, testIssuer, h.now, nil))
			form := preAuthorizedForm()
			if clientID != "" {
				form.Set("client_id", clientID)
			}
			req := extensionTokenRequest(t, form, header, nil)
			if got := req.AttestedClientAuthentication().ClientID; got != clientID {
				t.Fatalf("AttestedClientAuthentication().ClientID = %q, want %q", got, clientID)
			}
			_, err := h.server.AuthenticateAttestedClient(context.Background(), req.AttestedClientAuthentication())
			if wantOK {
				if err != nil {
					t.Fatalf("AuthenticateAttestedClient: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("code %q, want invalid_client", code)
			}
		})
	}
}

// TestExtensionGrantClientIDReadOnce covers client_id read the same way
// by TokenEndpointRequest.Parameters and AttestedClientAuthentication: a
// repeated client_id, an empty one among them, is refused by both, and
// never read as the attestation's client by one and as another client by
// the other. A single empty client_id is no client_id to either (RFC
// 6749 §3.1).
func TestExtensionGrantClientIDReadOnce(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	for name, values := range map[string][]string{
		"empty then another client": {"", "some-other-client"},
		"another client then empty": {"some-other-client", ""},
		"repeated":                  {testClientID.String(), testClientID.String()},
		"empty":                     {""},
	} {
		t.Run(name, func(t *testing.T) {
			instance := generateKey(t)
			header := dpopHeader(dpopProofAt(t, generateKey(t), testTokenEndpoint, "", h.now))
			header.Set("OAuth-Client-Attestation", draft12Attestation(t, attesterKey, nil, &instance.PublicKey, h.now, time.Hour))
			header.Set("OAuth-Client-Attestation-PoP", draft12PoP(t, instance, testIssuer, h.now, nil))
			form := preAuthorizedForm()
			form["client_id"] = values
			req := extensionTokenRequest(t, form, header, nil)
			params, paramsErr := req.Parameters()
			attested, err := h.server.AuthenticateAttestedClient(context.Background(), req.AttestedClientAuthentication())
			if len(values) == 1 {
				requireNoClientIDRead(t, params, paramsErr, attested, err)
				return
			}
			if paramsErr == nil {
				t.Fatalf("Parameters = %v, want a refusal", params)
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("AuthenticateAttestedClient code %q, want invalid_request", code)
			}
		})
	}
}

// requireNoClientIDRead checks a request with a single empty client_id
// was accepted by both readers, as no client_id at all.
func requireNoClientIDRead(t *testing.T, params map[string]string, paramsErr error, attested server.AttestedClient, err error) {
	t.Helper()
	if paramsErr != nil || err != nil {
		t.Fatalf("Parameters: %v, AuthenticateAttestedClient: %v", paramsErr, err)
	}
	if got, ok := params["client_id"]; ok || attested.Client.ID() != testClientID {
		t.Fatalf("client_id %q (present %v), authenticated %q", got, ok, attested.Client.ID())
	}
}
