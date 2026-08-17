package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// signRaw signs signingInput with key using the fixed-width R||S
// encoding JWS ES256 requires, for tests that need to hand-craft a
// validly signed token the public IssueIDToken API can't produce (e.g.
// one whose "aud" is an array rather than the single string
// IDTokenParams.Audience always sends).
func signRaw(t *testing.T, key *ecdsa.PrivateKey, signingInput string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	const coordSize = 32
	sig := make([]byte, 2*coordSize)
	r.FillBytes(sig[:coordSize])
	s.FillBytes(sig[coordSize:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

func jsonRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
