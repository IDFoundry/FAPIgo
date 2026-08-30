package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
)

// selfSignedTestClientCert generates a throwaway self-signed
// ExtKeyUsageClientAuth certificate — standing in for a real mTLS
// connection's own presented client certificate.
func selfSignedTestClientCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// mtlsFixture is newFixture's mTLS-bound counterpart: a signed access
// token whose "cnf" claim is x5t#S256 (not jkt), plus the matching
// client certificate.
type mtlsFixture struct {
	verifier    *resource.Verifier
	accessToken string
	jti         string
	cert        *x509.Certificate
	target      *url.URL
	revocation  *fakeRevocationChecker
	now         time.Time
}

func newMTLSFixture(t *testing.T) mtlsFixture {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	cert := selfSignedTestClientCert(t, "test-client")

	now := time.Now()
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	accessToken, jti, err := token.IssueAccessToken(token.AccessTokenParams{
		Signer: issuerKey, Algorithm: fapi.ES256, KeyID: "as-kid",
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
		ClientID: "client-1", Scope: "read write",
		Confirmation: &token.Confirmation{X5TS256: mtls.Thumbprint(cert)},
		Now:          now, Lifetime: 5 * time.Minute,
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}

	issuerURL, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	revocation := &fakeRevocationChecker{}
	jwtAccessTokens, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: issuerKey.Public()},
	}}}, issuerURL, testIssuer, fapi.ES256, 5*time.Minute, 8)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: jwtAccessTokens,
		Replay:       &fakeReplayStore{},
		Revocation:   revocation,
		Clock:        fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return mtlsFixture{verifier: v, accessToken: accessToken, jti: jti, cert: cert, target: target, revocation: revocation, now: now}
}

func TestVerifyAcceptsMTLSBoundToken(t *testing.T) {
	f := newMTLSFixture(t)

	authz, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization:   "Bearer " + f.accessToken,
		PeerCertificate: f.cert,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authz.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", authz.Subject)
	}
	if authz.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", authz.ClientID)
	}
	// mTLS binding never issues a DPoP nonce — the client never builds
	// DPoP proofs at all, so a nonce it would never use serves no
	// purpose.
	if authz.NextDPoPNonce != "" {
		t.Errorf("NextDPoPNonce = %q, want empty for an mTLS-bound request", authz.NextDPoPNonce)
	}
}

func TestVerifyRejectsMTLSBoundTokenWithWrongCertificate(t *testing.T) {
	f := newMTLSFixture(t)
	wrongCert := selfSignedTestClientCert(t, "wrong-client")

	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization:   "Bearer " + f.accessToken,
		PeerCertificate: wrongCert,
	})
	if err == nil {
		t.Fatalf("Verify(wrong certificate) = nil error, want error")
	}
}

// TestVerifyRejectsMTLSBoundTokenPresentedAsDPoP covers the explicit
// mechanism cross-check: an mTLS-bound token has no DPoP proof to
// verify at all (there is none — it was never issued one), so
// presenting it via the DPoP scheme must fail even before any
// thumbprint comparison happens.
func TestVerifyRejectsMTLSBoundTokenPresentedAsDPoP(t *testing.T) {
	f := newMTLSFixture(t)
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: dpopKey, Algorithm: fapi.ES256,
		Method: "GET", URL: f.target,
		AccessToken: f.accessToken,
		Now:         f.now,
		Random:      rand.Reader,
	})
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}

	_, err = f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization: "DPoP " + f.accessToken,
		DPoPProof:     proof,
	})
	if err == nil {
		t.Fatalf("Verify(mTLS-bound token presented via DPoP) = nil error, want error")
	}
}

// TestVerifyRejectsDPoPBoundTokenPresentedAsBearer is the symmetric
// case: newFixture's own token is DPoP-bound, so presenting it via
// Bearer+certificate must fail too, even with a certificate that would
// otherwise look plausible.
func TestVerifyRejectsDPoPBoundTokenPresentedAsBearer(t *testing.T) {
	f := newFixture(t)
	cert := selfSignedTestClientCert(t, "some-client")

	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization:   "Bearer " + f.accessToken,
		PeerCertificate: cert,
	})
	if err == nil {
		t.Fatalf("Verify(DPoP-bound token presented via Bearer) = nil error, want error")
	}
}

func TestVerifyRejectsRevokedMTLSBoundToken(t *testing.T) {
	f := newMTLSFixture(t)
	f.revocation.revoked = map[string]bool{f.jti: true}

	_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: f.target,
		Authorization:   "Bearer " + f.accessToken,
		PeerCertificate: f.cert,
	})
	if err == nil {
		t.Fatalf("Verify(revoked mTLS-bound token) = nil error, want error")
	}
}
