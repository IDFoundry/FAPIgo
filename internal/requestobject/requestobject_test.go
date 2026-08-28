package requestobject

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// signRaw signs signingInput with key using the fixed-width R||S
// encoding JWS ES256 requires (see internal/jose), for tests that need
// to hand-craft a validly signed token the public Create API can't
// produce (e.g. one missing an otherwise-always-present claim).
func signRaw(key *ecdsa.PrivateKey, signingInput string) (string, error) {
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	const coordSize = 32
	sig := make([]byte, 2*coordSize)
	r.FillBytes(sig[:coordSize])
	s.FillBytes(sig[coordSize:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

type memoryReplayChecker struct {
	seen map[string]bool
}

func newMemoryReplayChecker() *memoryReplayChecker {
	return &memoryReplayChecker{seen: make(map[string]bool)}
}

func (m *memoryReplayChecker) UseOnce(_ context.Context, jti string, _ time.Time) error {
	if m.seen[jti] {
		return errReplayed
	}
	m.seen[jti] = true
	return nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

const errReplayed = fakeErr("jti already used")

// spyReplayChecker records the (jti, expiresAt) it was last called with,
// for asserting on the TTL Verify passes to UseOnce rather than on
// eviction behavior a real store may not even implement.
type spyReplayChecker struct {
	jti       string
	expiresAt time.Time
}

func (s *spyReplayChecker) UseOnce(_ context.Context, jti string, expiresAt time.Time) error {
	s.jti = jti
	s.expiresAt = expiresAt
	return nil
}

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func jsonRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func testParameters(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		"response_type":         jsonRaw(t, "code"),
		"client_id":             jsonRaw(t, "client-123"),
		"redirect_uri":          jsonRaw(t, "https://rp.example/callback"),
		"scope":                 jsonRaw(t, "openid accounts"),
		"state":                 jsonRaw(t, "opaque-state"),
		"nonce":                 jsonRaw(t, "opaque-nonce"),
		"code_challenge":        jsonRaw(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		"code_challenge_method": jsonRaw(t, "S256"),
	}
}

func createTestObject(t *testing.T, key *ecdsa.PrivateKey, now time.Time, lifetime time.Duration) string {
	t.Helper()
	token, err := Create(CreateParams{
		Signer:     key,
		Algorithm:  fapi.ES256,
		ClientID:   "client-123",
		Audience:   "https://as.example",
		Now:        now,
		Lifetime:   lifetime,
		Parameters: testParameters(t),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return token
}

func basePolicy(now time.Time) VerifyPolicy {
	return VerifyPolicy{
		ExpectedClientID: "client-123",
		ExpectedAudience: "https://as.example",
		Algorithm:        fapi.ES256,
		Now:              now,
		MaxLifetime:      2 * time.Minute,
	}
}

func TestCreateVerifyRoundTrip(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if obj.ClaimedIssuer() != "client-123" {
		t.Fatalf("ClaimedIssuer() = %q, want %q", obj.ClaimedIssuer(), "client-123")
	}
	raw, ok := obj.Parameter("redirect_uri")
	if !ok {
		t.Fatalf("Parameter(redirect_uri) not found")
	}
	var redirectURI string
	if err := json.Unmarshal(raw, &redirectURI); err != nil || redirectURI != "https://rp.example/callback" {
		t.Fatalf("Parameter(redirect_uri) = %q, want %q", redirectURI, "https://rp.example/callback")
	}

	verified, err := obj.Verify(context.Background(), &key.PublicKey, basePolicy(now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.ClientID != "client-123" {
		t.Fatalf("ClientID = %q, want %q", verified.ClientID, "client-123")
	}
	if len(verified.Parameters) != len(testParameters(t)) {
		t.Fatalf("len(Parameters) = %d, want %d", len(verified.Parameters), len(testParameters(t)))
	}
	var scope string
	if err := json.Unmarshal(verified.Parameters["scope"], &scope); err != nil || scope != "openid accounts" {
		t.Fatalf("Parameters[scope] = %q, want %q", scope, "openid accounts")
	}
}

func TestVerifyWithKeyID(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "key-1",
		ClientID: "client-123", Audience: "https://as.example",
		Now: now, Lifetime: time.Minute, Parameters: testParameters(t),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if obj.KeyID() != "key-1" {
		t.Fatalf("KeyID() = %q, want %q", obj.KeyID(), "key-1")
	}
}

func TestCreateRejectsReservedClaimName(t *testing.T) {
	key := generateKey(t)
	params := testParameters(t)
	params["exp"] = jsonRaw(t, 12345)
	_, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, ClientID: "client-123",
		Audience: "https://as.example", Now: time.Now(), Lifetime: time.Minute, Parameters: params,
	})
	if err == nil {
		t.Fatalf("Create with reserved claim in Parameters = nil error, want error")
	}
}

func TestCreateRejectsInconsistentClientID(t *testing.T) {
	key := generateKey(t)
	params := testParameters(t)
	params["client_id"] = jsonRaw(t, "different-client")
	_, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, ClientID: "client-123",
		Audience: "https://as.example", Now: time.Now(), Lifetime: time.Minute, Parameters: params,
	})
	if err == nil {
		t.Fatalf("Create with mismatched client_id parameter = nil error, want error")
	}
}

func TestParseRejectsWrongType(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"client-123","aud":"https://as.example","exp":9999999999}`,
	))
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	if _, err := Parse(token); !errors.Is(err, ErrWrongType) {
		t.Fatalf("Parse(wrong typ) = %v, want ErrWrongType", err)
	}
}

// RFC 9101 §10.8 frames the "typ" header as something "one would"
// explicitly include, not a requirement, and warns that mandating it
// "will break most existing deployments, as existing clients are
// already commonly using untyped Request Objects" - an absent "typ"
// must parse successfully, not just a correctly-set one.
func TestParseAcceptsMissingType(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"client-123","aud":"https://as.example","exp":9999999999}`,
	))
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	if _, err := Parse(token); err != nil {
		t.Fatalf("Parse(missing typ) = %v, want nil error", err)
	}
}

// RFC 7515 §4.1.9/§5.3 single "typ" out as the one JOSE header value
// compared per RFC 2045 media-type rules, not ordinary case-sensitive
// JSON string comparison — those rules are explicitly case insensitive,
// and a value with no "/" is treated as "application/"-prefixed. The
// OIDF conformance suite deliberately sends a randomized-case "typ" to
// check exactly this (JAR-4); an "application/"-prefixed value is the
// same requirement applied to the other RFC 2045 convention.
func TestParseAcceptsCaseInsensitiveType(t *testing.T) {
	for _, typ := range []string{
		"OautH-auThZ-REQ+jWt",
		"APPLICATION/oauth-authz-req+jwt",
		"Application/OAuth-Authz-Req+JWT",
	} {
		headerJSON, err := json.Marshal(map[string]string{"alg": "ES256", "typ": typ})
		if err != nil {
			t.Fatalf("marshal header: %v", err)
		}
		header := base64.RawURLEncoding.EncodeToString(headerJSON)
		payload := base64.RawURLEncoding.EncodeToString([]byte(
			`{"iss":"client-123","aud":"https://as.example","exp":9999999999}`,
		))
		token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))

		if _, err := Parse(token); err != nil {
			t.Fatalf("Parse(typ=%q) = %v, want nil error", typ, err)
		}
	}
}

func TestParseRejectsMissingRequiredClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"oauth-authz-req+jwt"}`))
	cases := []string{
		`{"aud":"https://as.example","exp":9999999999}`,   // missing iss
		`{"iss":"client-123","exp":9999999999}`,           // missing aud
		`{"iss":"client-123","aud":"https://as.example"}`, // missing exp
	}
	for _, payloadJSON := range cases {
		payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
		token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		if _, err := Parse(token); !errors.Is(err, ErrMalformedClaims) {
			t.Fatalf("Parse(%s) = %v, want ErrMalformedClaims", payloadJSON, err)
		}
	}
}

func TestParseRejectsClientIDIssuerMismatch(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"oauth-authz-req+jwt"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"client-123","aud":"https://as.example","exp":9999999999,"client_id":"different-client"}`,
	))
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	if _, err := Parse(token); !errors.Is(err, ErrClientIDIssuerMismatch) {
		t.Fatalf("Parse(client_id != iss) = %v, want ErrClientIDIssuerMismatch", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key := generateKey(t)
	other := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj.Verify(context.Background(), &other.PublicKey, basePolicy(now)); err == nil {
		t.Fatalf("Verify(wrong key) = nil error, want error")
	}
}

func TestVerifyRejectsAlgorithmConfusion(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.Algorithm = fapi.PS256
	if _, err := obj.Verify(context.Background(), &key.PublicKey, policy); err == nil {
		t.Fatalf("Verify(policy alg PS256, header alg ES256) = nil error, want error")
	}
}

func TestVerifyRejectsIssuerMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.ExpectedClientID = "different-client"
	if _, err := obj.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("Verify(wrong client id) = %v, want ErrIssuerMismatch", err)
	}
}

// RFC 7519 §4.1.3 permits "aud" to be a JSON array as well as a single
// string, and the OIDF conformance suite deliberately sends an array
// mixing the AS's own issuer identifier with unrelated values to check
// this is honored (RFC7519-4.1.3) - a request object must be accepted
// as long as the expected audience is somewhere in the array, not only
// when the array holds nothing else.
func TestVerifyAcceptsAudienceArrayContainingExpected(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "client-123",
		"aud": []string{"https://other1.example.com", "https://as.example", "invalid"},
		"exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signRaw(key, signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := signingInput + "." + sig

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj.Verify(context.Background(), &key.PublicKey, basePolicy(now)); err != nil {
		t.Fatalf("Verify(aud array containing expected) = %v, want nil error", err)
	}
}

func TestVerifyRejectsAudienceMismatch(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.ExpectedAudience = "https://other-as.example"
	if _, err := obj.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Verify(wrong audience) = %v, want ErrAudienceMismatch", err)
	}
}

func TestVerifyRejectsExpiredObject(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now.Add(2 * time.Minute))
	if _, err := obj.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsLifetimeExceeded(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, 10*time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj.Verify(context.Background(), &key.PublicKey, basePolicy(now)); !errors.Is(err, ErrLifetimeExceeded) {
		t.Fatalf("Verify(exceeds max lifetime) = %v, want ErrLifetimeExceeded", err)
	}
}

// FAPI 2.0 Message Signing Final §5.3.1 (FAPI2-MS-ID1-5.3.1-3) requires
// rejecting a request object whose claimed validity window is
// unreasonably long — an ancient nbf paired with a normal, unexpired
// exp must be rejected just as readily as a normal nbf paired with an
// exp pushed too far into the future (TestVerifyRejectsLifetimeExceeded
// above) is. Regression test: this object's nbf and exp individually
// pass every other check (exp is a minute in the future, well under
// MaxLifetime; nbf isn't in the future so ErrNotYetValid can't fire) —
// only the nbf-age check this test exists for catches it.
func TestVerifyRejectsNotBeforeTooOld(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now.Add(-5*time.Minute), 6*time.Minute)

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj.Verify(context.Background(), &key.PublicKey, basePolicy(now)); !errors.Is(err, ErrNotBeforeTooOld) {
		t.Fatalf("Verify(ancient nbf) = %v, want ErrNotBeforeTooOld", err)
	}
}

// FAPI 2.0 Message Signing Final §5.3.1 mandates nbf on a request
// object; the base FAPI 2.0 Security Profile does not. VerifyPolicy
// models that as RequireNotBefore, set only under the message-signing
// profile — a missing nbf must be rejected when it's true...
func TestVerifyRejectsMissingNotBeforeWhenRequired(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "client-123", "aud": "https://as.example", "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signRaw(key, signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := signingInput + "." + sig

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.RequireNotBefore = true
	if _, err := obj.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrMissingNotBefore) {
		t.Fatalf("Verify(no nbf, required) = %v, want ErrMissingNotBefore", err)
	}
}

// ...but accepted, as before, when it's false (the default, and what
// the base FAPI 2.0 Security Profile uses).
func TestVerifyAcceptsMissingNotBeforeWhenNotRequired(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "client-123", "aud": "https://as.example", "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signRaw(key, signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := signingInput + "." + sig

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj.Verify(context.Background(), &key.PublicKey, basePolicy(now)); err != nil {
		t.Fatalf("Verify(no nbf, not required) = %v, want nil error", err)
	}
}

// FAPI-CIBA's backchannel authentication request has no PAR-style
// single-use request_uri wrapper of its own, so unlike PAR's request
// object, jti is mandatory there. VerifyPolicy models that as
// RequireJTI, set only by that caller — a missing jti must be rejected
// when it's true...
func TestVerifyRejectsMissingJTIWhenRequired(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "client-123", "aud": "https://as.example", "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signRaw(key, signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := signingInput + "." + sig

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.RequireJTI = true
	if _, err := obj.Verify(context.Background(), &key.PublicKey, policy); !errors.Is(err, ErrMissingJTI) {
		t.Fatalf("Verify(no jti, required) = %v, want ErrMissingJTI", err)
	}
}

// ...but accepted, as before, when it's false (the default, and what
// PAR's own request object verification uses).
func TestVerifyAcceptsMissingJTIWhenNotRequired(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "client-123", "aud": "https://as.example", "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signRaw(key, signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := signingInput + "." + sig

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj.Verify(context.Background(), &key.PublicKey, basePolicy(now)); err != nil {
		t.Fatalf("Verify(no jti, not required) = %v, want nil error", err)
	}
}

func TestVerifyDetectsReplay(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	replay := newMemoryReplayChecker()
	policy := basePolicy(now)
	policy.Replay = replay

	obj1, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj1.Verify(context.Background(), &key.PublicKey, policy); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	obj2, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := obj2.Verify(context.Background(), &key.PublicKey, policy); err == nil {
		t.Fatalf("second Verify (replay) = nil error, want error")
	}
}

// The replay TTL must cover the same MaxClockSkew the expiry check
// grants (line 171), or a request object could still be accepted in
// (ExpiresAt, ExpiresAt+skew] after its jti's replay record has already
// expired.
func TestVerifyReplayTTLCoversClockSkew(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	spy := &spyReplayChecker{}
	policy := basePolicy(now)
	policy.MaxClockSkew = 30 * time.Second
	policy.Replay = spy

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := obj.Verify(context.Background(), &key.PublicKey, policy)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := verified.ExpiresAt.Add(policy.MaxClockSkew)
	if !spy.expiresAt.Equal(want) {
		t.Fatalf("replay TTL = %v, want %v (ExpiresAt + MaxClockSkew)", spy.expiresAt, want)
	}
}

// Regression guard: with no clock skew configured, the replay TTL must
// equal ExpiresAt exactly — proving the TTL tracks MaxClockSkew rather
// than being unconditionally padded.
func TestVerifyReplayTTLEqualsExpiryWhenNoSkew(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	token := createTestObject(t, key, now, time.Minute)

	spy := &spyReplayChecker{}
	policy := basePolicy(now)
	policy.MaxClockSkew = 0
	policy.Replay = spy

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := obj.Verify(context.Background(), &key.PublicKey, policy)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !spy.expiresAt.Equal(verified.ExpiresAt) {
		t.Fatalf("replay TTL = %v, want %v (ExpiresAt, since MaxClockSkew is zero)", spy.expiresAt, verified.ExpiresAt)
	}
}

// Neither RFC 9101 nor FAPI 2.0 Message Signing Final requires a
// request object to carry a jti - message-signing's own replay defense
// is its tightly-bounded nbf/exp window, not a jti claim - and the OIDF
// conformance suite's own request objects never include one under the
// plain FAPI2 profile. So a request object missing jti must still
// verify successfully even with a replay checker configured; it just
// means that particular object skips replay-by-jti.
func TestVerifySucceedsWithoutJTIWhenReplayConfigured(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"oauth-authz-req+jwt"}`))
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "client-123", "aud": "https://as.example", "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Create always sets jti, so a validly signed object lacking one has
	// to be hand-crafted rather than produced through the public API.
	unsignedHeader := header
	unsignedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := unsignedHeader + "." + unsignedPayload
	sig, err := signRaw(key, signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := signingInput + "." + sig

	obj, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	policy := basePolicy(now)
	policy.Replay = newMemoryReplayChecker()
	if _, err := obj.Verify(context.Background(), &key.PublicKey, policy); err != nil {
		t.Fatalf("Verify(no jti, replay configured) = %v, want nil error", err)
	}
}
