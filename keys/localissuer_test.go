package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

const localIssuer = "https://as.example"

func mustIssuer(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseIssuerURL(localIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	return u
}

// purposeRecorder is a KeyManager that records the signing purpose it
// was asked about.
type purposeRecorder struct {
	asked []keys.SigningPurpose
	info  keys.PublicKeyInfo
}

func (r *purposeRecorder) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, nil
}

func (r *purposeRecorder) PublicKey(_ context.Context, p keys.SigningPurpose, _ fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	r.asked = append(r.asked, p)
	return r.info, nil
}

func TestNewLocalIssuerKeysRequiresIssuerAndManager(t *testing.T) {
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	if _, err := keys.NewLocalIssuerKeys(fapi.URL{}, km); err == nil {
		t.Error("NewLocalIssuerKeys(zero issuer) = nil error, want error")
	}
	if _, err := keys.NewLocalIssuerKeys(mustIssuer(t), nil); err == nil {
		t.Error("NewLocalIssuerKeys(nil manager) = nil error, want error")
	}
}

// TestLocalIssuerKeysResolvesTheSigningKey covers the same-process AS
// and RS case end to end with a real KeyManager: the key resolved for
// access-token verification is the one the AS signs access tokens with.
func TestLocalIssuerKeysResolvesTheSigningKey(t *testing.T) {
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	src, err := keys.NewLocalIssuerKeys(mustIssuer(t), km)
	if err != nil {
		t.Fatalf("NewLocalIssuerKeys: %v", err)
	}
	want, err := km.PublicKey(context.Background(), keys.AccessTokenSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	set, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: localIssuer, Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != want.KeyID || set.Keys[0].Algorithm != fapi.ES256 ||
		!set.Keys[0].PublicKey.(*ecdsa.PublicKey).Equal(want.PublicKey) {
		t.Fatalf("ResolveIssuerKeys = %+v, want the access-token signing key %q", set.Keys, want.KeyID)
	}
}

func TestLocalIssuerKeysMapsEachVerificationPurpose(t *testing.T) {
	cases := map[keys.IssuerVerificationPurpose]keys.SigningPurpose{
		keys.AccessTokenVerification: keys.AccessTokenSigning,
		keys.JARMVerification:        keys.JARMSigning,
		keys.IDTokenVerification:     keys.IDTokenSigning,
		keys.UserInfoVerification:    keys.UserInfoSigning,
	}
	for verify, sign := range cases {
		rec := &purposeRecorder{info: keys.PublicKeyInfo{KeyID: "k"}}
		src, err := keys.NewLocalIssuerKeys(mustIssuer(t), rec)
		if err != nil {
			t.Fatalf("NewLocalIssuerKeys: %v", err)
		}
		if _, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{Issuer: localIssuer, Purpose: verify, Algorithm: fapi.ES256}); err != nil {
			t.Fatalf("ResolveIssuerKeys(%v): %v", verify, err)
		}
		if len(rec.asked) != 1 || rec.asked[0] != sign {
			t.Errorf("purpose %v asked the KeyManager for %v, want %v", verify, rec.asked, sign)
		}
	}
}

// TestLocalIssuerKeysPublishesEveryRotatingKey covers what a copied
// "return PublicKey" adapter gets wrong: during a rotation's overlap
// window a token signed with the outgoing key must still verify.
func TestLocalIssuerKeysPublishesEveryRotatingKey(t *testing.T) {
	outgoing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	newest, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	src, err := keys.NewLocalIssuerKeys(mustIssuer(t), &rotatingSigner{outgoing: outgoing, newest: newest, outgoingKID: "outgoing-kid", newestKID: "newest-kid"})
	if err != nil {
		t.Fatalf("NewLocalIssuerKeys: %v", err)
	}
	resolve := func(kid string) keys.IssuerKeySet {
		t.Helper()
		set, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
			Issuer: localIssuer, Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256, KeyID: kid,
		})
		if err != nil {
			t.Fatalf("ResolveIssuerKeys(kid %q): %v", kid, err)
		}
		return set
	}
	if set := resolve(""); len(set.Keys) != 2 {
		t.Errorf("no kid: %d keys, want 2 (outgoing + newest)", len(set.Keys))
	}
	if set := resolve("outgoing-kid"); len(set.Keys) != 1 || set.Keys[0].KeyID != "outgoing-kid" {
		t.Errorf("outgoing kid: %+v, want just the outgoing key", set.Keys)
	}
	if set := resolve("unknown-kid"); len(set.Keys) != 0 {
		t.Errorf("unknown kid: %+v, want no keys", set.Keys)
	}
}

func TestLocalIssuerKeysRejectsForeignIssuerAndUnknownPurpose(t *testing.T) {
	src, err := keys.NewLocalIssuerKeys(mustIssuer(t), &purposeRecorder{})
	if err != nil {
		t.Fatalf("NewLocalIssuerKeys: %v", err)
	}
	if _, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: "https://other-as.example", Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256,
	}); err == nil {
		t.Error("ResolveIssuerKeys(foreign issuer) = nil error, want error")
	}
	if _, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: localIssuer, Purpose: keys.IssuerVerificationPurpose(99), Algorithm: fapi.ES256,
	}); err == nil {
		t.Error("ResolveIssuerKeys(unknown purpose) = nil error, want error")
	}
}

func TestLocalIssuerKeysDeclaresNoLiveFetch(t *testing.T) {
	src, err := keys.NewLocalIssuerKeys(mustIssuer(t), &purposeRecorder{})
	if err != nil {
		t.Fatalf("NewLocalIssuerKeys: %v", err)
	}
	var asserter keys.KeySourceAssurance = src
	if !asserter.Capabilities().LiveFetchHardened {
		t.Fatal("Capabilities().LiveFetchHardened = false, want true")
	}
}
