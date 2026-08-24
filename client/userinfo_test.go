package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

const userInfoTestSubject = "end-user-1"

func userInfoTestTokens() client.TokenSet {
	return client.TokenSet{
		AccessToken:   fapi.NewSecret("test-access-token"),
		HasIDToken:    true,
		IDTokenClaims: client.IDTokenClaims{Subject: userInfoTestSubject},
	}
}

// newUserInfoTestClient builds a client wired to ts's "/userinfo" path,
// with a UserInfoVerification issuer key resolving to userInfoKey (if
// non-nil). mutateCfg/mutateDeps, if non-nil, run after the baseline
// setup, so a test can layer on encryption config or a Decryption
// dependency.
func newUserInfoTestClient(t *testing.T, ts *httptest.Server, userInfoKey *ecdsa.PublicKey, mutateCfg func(*client.Config), mutateDeps func(*client.Dependencies)) *client.Client {
	t.Helper()
	cfg := validConfig(t)
	cfg.Algorithms.UserInfo = fapi.ES256
	userInfoURL, err := fapi.ParseEndpointURL(ts.URL+"/userinfo", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(userinfo): %v", err)
	}
	cfg.Endpoints.UserInfo = userInfoURL
	if mutateCfg != nil {
		mutateCfg(&cfg)
	}

	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	issuerKeys := map[keys.IssuerVerificationPurpose]crypto.PublicKey{}
	if userInfoKey != nil {
		issuerKeys[keys.UserInfoVerification] = userInfoKey
	}
	deps.IssuerKeys = &fakeIssuerKeySource{keys: issuerKeys}
	if mutateDeps != nil {
		mutateDeps(&deps)
	}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

func signUserInfoJWS(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, KeyID: "userinfo-kid"}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

func TestFetchUserInfoAcceptsPlainJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": userInfoTestSubject, "name": "Ada"})
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, nil, nil, nil)
	info, err := c.FetchUserInfo(context.Background(), userInfoTestTokens())
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if info.Subject != userInfoTestSubject {
		t.Errorf("Subject = %q, want %q", info.Subject, userInfoTestSubject)
	}
	var name string
	if err := json.Unmarshal(info.Parameters["name"], &name); err != nil || name != "Ada" {
		t.Errorf("Parameters[name] = %s (err %v), want \"Ada\"", info.Parameters["name"], err)
	}
	if _, ok := info.Parameters["sub"]; ok {
		t.Errorf("Parameters contains sub, want it excluded")
	}
}

func TestFetchUserInfoVerifiesSignedJWTResponse(t *testing.T) {
	userInfoKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate userinfo key: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		compact := signUserInfoJWS(t, userInfoKey, map[string]any{"sub": userInfoTestSubject, "name": "Ada"})
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(compact))
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, &userInfoKey.PublicKey, nil, nil)
	info, err := c.FetchUserInfo(context.Background(), userInfoTestTokens())
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if info.Subject != userInfoTestSubject {
		t.Errorf("Subject = %q, want %q", info.Subject, userInfoTestSubject)
	}
}

func TestFetchUserInfoRejectsSignedJWTWithWrongKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		compact := signUserInfoJWS(t, signingKey, map[string]any{"sub": userInfoTestSubject})
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(compact))
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, &wrongKey.PublicKey, nil, nil)
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(wrong issuer key) = nil error, want error")
	}
}

func TestFetchUserInfoDecryptsSignedThenEncryptedResponse(t *testing.T) {
	userInfoKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate userinfo key: %v", err)
	}
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.UserInfoDecryption: fapi.ECDHESA256KW,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	info, err := decrypter.EncryptionPublicKey(context.Background(), keys.UserInfoDecryption, fapi.ECDHESA256KW)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signed := signUserInfoJWS(t, userInfoKey, map[string]any{"sub": userInfoTestSubject, "name": "Ada"})
		encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
			Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM,
			RecipientKey: info.PublicKey, ContentType: "JWT", Plaintext: []byte(signed),
		})
		if err != nil {
			t.Fatalf("jwe.Encrypt: %v", err)
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(encrypted))
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, &userInfoKey.PublicKey, func(cfg *client.Config) {
		cfg.Algorithms.UserInfoKeyManagement = fapi.ECDHESA256KW
		cfg.Algorithms.UserInfoContentEncryption = fapi.A256GCM
	}, func(deps *client.Dependencies) {
		deps.Decryption = decrypter
	})

	got, err := c.FetchUserInfo(context.Background(), userInfoTestTokens())
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if got.Subject != userInfoTestSubject {
		t.Errorf("Subject = %q, want %q", got.Subject, userInfoTestSubject)
	}
}

func TestFetchUserInfoRejectsSubjectMismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "someone-else"})
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, nil, nil, nil)
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(sub mismatch) = nil error, want error")
	}
}

func TestFetchUserInfoRejectsMissingSubClaim(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "Ada"})
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, nil, nil, nil)
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(no sub) = nil error, want error")
	}
}

func TestFetchUserInfoRejectsWhenNoIDToken(t *testing.T) {
	tracker := &trackingHTTPClient{}
	cfg := validConfig(t)
	cfg.Algorithms.UserInfo = fapi.ES256
	userInfoURL, err := fapi.ParseEndpointURL("https://as.example.com/userinfo")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg.Endpoints.UserInfo = userInfoURL
	deps := validDependencies(t)
	deps.HTTP = tracker

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	tokens := userInfoTestTokens()
	tokens.HasIDToken = false
	if _, err := c.FetchUserInfo(context.Background(), tokens); err == nil {
		t.Fatalf("FetchUserInfo(no ID token) = nil error, want error")
	}
	if tracker.called {
		t.Errorf("HTTP client was called; want FetchUserInfo to fail before any request")
	}
}

func TestFetchUserInfoRejectsWhenEndpointNotConfigured(t *testing.T) {
	tracker := &trackingHTTPClient{}
	deps := validDependencies(t)
	deps.HTTP = tracker

	c, err := client.New(validConfig(t), deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(no endpoint configured) = nil error, want error")
	}
	if tracker.called {
		t.Errorf("HTTP client was called; want FetchUserInfo to fail before any request")
	}
}

func TestFetchUserInfoRejectsUnexpectedContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, nil, nil, nil)
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(unexpected content type) = nil error, want error")
	}
}

func TestFetchUserInfoRejectsNon200Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "insufficient_scope"})
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, nil, nil, nil)
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(403) = nil error, want error")
	}
}

// TestFetchUserInfoRejectsPlainJSONWhenEncryptionRequired confirms the
// same anti-downgrade discipline validateIDToken applies to an
// encrypted ID token: a client registered to expect an encrypted
// UserInfo response must reject a plain one, not silently accept the
// downgrade.
func TestFetchUserInfoRejectsPlainJSONWhenEncryptionRequired(t *testing.T) {
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.UserInfoDecryption: fapi.ECDHESA256KW,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": userInfoTestSubject})
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, nil, func(cfg *client.Config) {
		cfg.Algorithms.UserInfoKeyManagement = fapi.ECDHESA256KW
		cfg.Algorithms.UserInfoContentEncryption = fapi.A256GCM
	}, func(deps *client.Dependencies) {
		deps.Decryption = decrypter
	})
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(plain JSON, encryption required) = nil error, want error")
	}
}

// TestFetchUserInfoRejectsEncryptedWhenNotExpected is the symmetric
// anti-downgrade direction: an encrypted response arriving when this
// client never registered for one must also be rejected, not decrypted
// on the strength of whatever the response's own shape claims.
func TestFetchUserInfoRejectsEncryptedWhenNotExpected(t *testing.T) {
	userInfoKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate userinfo key: %v", err)
	}
	decrypter, err := ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.UserInfoDecryption: fapi.ECDHESA256KW,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	recipientInfo, err := decrypter.EncryptionPublicKey(context.Background(), keys.UserInfoDecryption, fapi.ECDHESA256KW)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signed := signUserInfoJWS(t, userInfoKey, map[string]any{"sub": userInfoTestSubject})
		encrypted, err := jwe.Encrypt(jwe.EncryptRequest{
			Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM,
			RecipientKey: recipientInfo.PublicKey, ContentType: "JWT", Plaintext: []byte(signed),
		})
		if err != nil {
			t.Fatalf("jwe.Encrypt: %v", err)
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(encrypted))
	}))
	defer ts.Close()

	// Note: this client's Algorithms.UserInfoKeyManagement is left zero
	// (never configured for encryption).
	c := newUserInfoTestClient(t, ts, &userInfoKey.PublicKey, nil, nil)
	if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err == nil {
		t.Fatalf("FetchUserInfo(encrypted, not expected) = nil error, want error")
	}
}
