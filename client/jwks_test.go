package client_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
)

// fakePublicKeyDecrypter is a keys.Decrypter fake that returns a real
// RSA public key per decryption purpose — unlike fakeDecrypter
// (client_test.go), which always errors, this exercises PublicJWKS's
// encryption-key path.
type fakePublicKeyDecrypter struct {
	keys map[keys.DecryptionPurpose]*rsa.PrivateKey
}

func newFakePublicKeyDecrypter(t *testing.T, purposes ...keys.DecryptionPurpose) *fakePublicKeyDecrypter {
	t.Helper()
	d := &fakePublicKeyDecrypter{keys: map[keys.DecryptionPurpose]*rsa.PrivateKey{}}
	for _, p := range purposes {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key for purpose %v: %v", p, err)
		}
		d.keys[p] = priv
	}
	return d
}

func (d *fakePublicKeyDecrypter) keyID(purpose keys.DecryptionPurpose) string {
	return fmt.Sprintf("enc-kid-%d", purpose)
}

func (d *fakePublicKeyDecrypter) UnwrapContentEncryptionKey(context.Context, keys.UnwrapRequest) ([]byte, error) {
	return nil, fmt.Errorf("fakePublicKeyDecrypter: not implemented")
}

func (d *fakePublicKeyDecrypter) EncryptionPublicKey(_ context.Context, purpose keys.DecryptionPurpose, _ fapi.KeyManagementAlgorithm) (keys.PublicKeyInfo, error) {
	priv, ok := d.keys[purpose]
	if !ok {
		return keys.PublicKeyInfo{}, fmt.Errorf("fakePublicKeyDecrypter: no key for purpose %v", purpose)
	}
	return keys.PublicKeyInfo{KeyID: d.keyID(purpose), PublicKey: &priv.PublicKey}, nil
}

func TestPublicJWKSBaselineProfileIncludesOnlyClientAuthentication(t *testing.T) {
	cfg := validConfig(t)
	deps := validDependencies(t)
	km := deps.Keys.(*fakeKeyManager)

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	set, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1", len(set.Keys))
	}
	if set.Keys[0].KeyID() != km.keyID(keys.ClientAuthentication) {
		t.Fatalf("KeyID() = %q, want %q", set.Keys[0].KeyID(), km.keyID(keys.ClientAuthentication))
	}
}

func TestPublicJWKSMessageSigningProfileIncludesRequestObjectKey(t *testing.T) {
	cfg := validConfig(t)
	cfg.Profile = client.ProfileFAPISecurityWithMessageSigning
	cfg.Algorithms.RequestObject = fapi.ES256
	cfg.Algorithms.JARM = fapi.ES256
	cfg.Limits.RequestObjectLifetime = time.Minute
	cfg.Limits.MaxJARMResponseLifetime = time.Minute
	deps := validDependencies(t)
	km := deps.Keys.(*fakeKeyManager)

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	set, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("len(Keys) = %d, want 2", len(set.Keys))
	}
	seen := map[string]bool{}
	for _, k := range set.Keys {
		seen[k.KeyID()] = true
	}
	for _, want := range []keys.SigningPurpose{keys.ClientAuthentication, keys.RequestObjectSigning} {
		if !seen[km.keyID(want)] {
			t.Fatalf("Keys missing kid %q; got %v", km.keyID(want), seen)
		}
	}
}

// TestPublicJWKSExcludesDPoPKey confirms DPoPProofSigning's key never
// appears in PublicJWKS's output regardless of profile — RFC 9449
// embeds a DPoP proof's public key directly in the proof's own header,
// never via a discoverable JWKS.
func TestPublicJWKSExcludesDPoPKey(t *testing.T) {
	cfg := validConfig(t)
	cfg.Profile = client.ProfileFAPISecurityWithMessageSigning
	cfg.Algorithms.RequestObject = fapi.ES256
	cfg.Algorithms.JARM = fapi.ES256
	cfg.Limits.RequestObjectLifetime = time.Minute
	cfg.Limits.MaxJARMResponseLifetime = time.Minute
	deps := validDependencies(t)
	km := deps.Keys.(*fakeKeyManager)

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	set, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	dpopKID := km.keyID(keys.DPoPProofSigning)
	for _, k := range set.Keys {
		if k.KeyID() == dpopKID {
			t.Fatalf("PublicJWKS included the DPoP proof signing key (kid %q); it must not", dpopKID)
		}
	}
}

func TestPublicJWKSIncludesEncryptionKeyWhenConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.IDTokenKeyManagement = fapi.RSAOAEP256
	cfg.Algorithms.IDTokenContentEncryption = fapi.A256GCM
	deps := validDependencies(t)
	km := deps.Keys.(*fakeKeyManager)
	dec := newFakePublicKeyDecrypter(t, keys.IDTokenDecryption)
	deps.Decryption = dec

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	set, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("len(Keys) = %d, want 2 (ClientAuthentication + IDTokenDecryption)", len(set.Keys))
	}
	seen := map[string]bool{}
	for _, k := range set.Keys {
		seen[k.KeyID()] = true
	}
	if !seen[km.keyID(keys.ClientAuthentication)] {
		t.Fatalf("Keys missing the signing kid; got %v", seen)
	}
	if !seen[dec.keyID(keys.IDTokenDecryption)] {
		t.Fatalf("Keys missing the encryption kid; got %v", seen)
	}
}

// TestPublicJWKSMarshalsEncryptionKeyWithUseEnc confirms the published
// encryption key actually carries "use":"enc" (not "sig", and not
// omitted) — the member a verifier needs to tell it apart from the
// signing keys in the same set.
func TestPublicJWKSMarshalsEncryptionKeyWithUseEnc(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.IDTokenKeyManagement = fapi.RSAOAEP256
	cfg.Algorithms.IDTokenContentEncryption = fapi.A256GCM
	deps := validDependencies(t)
	dec := newFakePublicKeyDecrypter(t, keys.IDTokenDecryption)
	deps.Decryption = dec

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	set, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}

	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	var encKey map[string]any
	for _, k := range decoded.Keys {
		if k["kid"] == dec.keyID(keys.IDTokenDecryption) {
			encKey = k
		}
	}
	if encKey == nil {
		t.Fatalf("decoded JWKS missing the encryption key: %v", decoded.Keys)
	}
	if encKey["use"] != "enc" {
		t.Fatalf("encryption key use = %v, want %q", encKey["use"], "enc")
	}
	if encKey["alg"] != "RSA-OAEP-256" {
		t.Fatalf("encryption key alg = %v, want %q", encKey["alg"], "RSA-OAEP-256")
	}
	if encKey["kty"] != "RSA" {
		t.Fatalf("encryption key kty = %v, want RSA", encKey["kty"])
	}
	if _, ok := encKey["d"]; ok {
		t.Fatalf("published JWK contains private key material: %v", encKey)
	}
}

// emptyKIDKeyManager is a keys.KeyManager whose PublicKey always
// succeeds but reports an empty kid — the case PublicJWKS must reject
// rather than publish an unidentifiable key.
type emptyKIDKeyManager struct{ pub *rsa.PublicKey }

func (m emptyKIDKeyManager) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, fmt.Errorf("emptyKIDKeyManager: not implemented")
}

func (m emptyKIDKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{KeyID: "", PublicKey: m.pub}, nil
}

func TestPublicJWKSRejectsEmptyKeyIDFromKeyManager(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	cfg := validConfig(t)
	cfg.Algorithms.ClientAuthentication = fapi.PS256
	deps := validDependencies(t)
	deps.Keys = emptyKIDKeyManager{pub: &priv.PublicKey}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.PublicJWKS(context.Background()); err == nil {
		t.Fatal("PublicJWKS(empty kid) = nil error, want error")
	}
}

// rotatingClientKeyManager is a keys.RotatingKeyManager fake proving
// PublicJWKS takes the wider PublicKeys set (mirroring
// server.PublicJWKS's own rotation-aware behavior) rather than always
// falling back to the single-key PublicKey path.
type rotatingClientKeyManager struct {
	outgoing, newest *fakeKeyManager
}

func (m *rotatingClientKeyManager) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	return m.newest.Sign(ctx, req)
}

func (m *rotatingClientKeyManager) PublicKey(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return m.newest.PublicKey(ctx, purpose, algorithm)
}

func (m *rotatingClientKeyManager) PublicKeys(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.SigningKeySet, error) {
	outgoing, err := m.outgoing.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return keys.SigningKeySet{}, err
	}
	// fakeKeyManager.keyID is purpose-derived only, so the outgoing and
	// newest backends (both registered for the same purpose) would
	// otherwise report the same kid — override them here so PublicJWKS's
	// dedup-by-kid logic sees two distinct keys, as a real rotation
	// would produce.
	outgoing.KeyID = "outgoing-kid"
	newest, err := m.newest.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return keys.SigningKeySet{}, err
	}
	newest.KeyID = "newest-kid"
	return keys.SigningKeySet{Keys: []keys.PublicKeyInfo{outgoing, newest}}, nil
}

func TestPublicJWKSPublishesRotatingSigningKeySet(t *testing.T) {
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Keys = &rotatingClientKeyManager{
		outgoing: newFakeKeyManager(t, keys.ClientAuthentication),
		newest:   newFakeKeyManager(t, keys.ClientAuthentication),
	}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	set, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("len(Keys) = %d, want 2 (outgoing + newest)", len(set.Keys))
	}
}

// erroringClientKeyManager is a keys.KeyManager whose PublicKey always
// fails — PublicJWKS must propagate that error, not swallow it.
type erroringClientKeyManager struct{}

func (erroringClientKeyManager) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, errPublicJWKSKeyManagerUnavailable
}

func (erroringClientKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{}, errPublicJWKSKeyManagerUnavailable
}

var errPublicJWKSKeyManagerUnavailable = fmt.Errorf("key manager unavailable")

func TestPublicJWKSPropagatesKeyManagerError(t *testing.T) {
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Keys = erroringClientKeyManager{}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.PublicJWKS(context.Background()); err == nil {
		t.Fatal("PublicJWKS(erroring key manager) = nil error, want error")
	}
}
