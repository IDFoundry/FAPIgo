package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// selfSignedTestClientCertForKey is selfSignedTestClientCertWithSAN
// for priv, instead of a fresh key.
func selfSignedTestClientCertForKey(t *testing.T, priv *ecdsa.PrivateKey, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-mtls-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	mutate(template)
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

// requestClientCredentialsWithCertificate asks srv for a client
// credentials token as rpID, authenticated by cert alone.
func requestClientCredentialsWithCertificate(t *testing.T, srv *server.Server, f *automaticRegistrationFixture, cert *x509.Certificate) error {
	t.Helper()
	_, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("grant_type", "client_credentials"),
			formParam("client_id", f.rpID),
			formParam("scope", "accounts"),
		}},
		DPoPProofs:      []string{createDPoPProof(t, generateKey(t), f.now)},
		PeerCertificate: cert,
	})
	return err
}

// TestAutomaticRegistrationTLSClientAuthRequiresRPKey covers OpenID
// Federation 1.0 §12.1.1.2: an automatically registered RP must prove
// possession of "one of the RP's private keys", whose "corresponding
// public key MUST be in the Entity's RP JWK Set". A certificate under a
// trusted CA naming the RP's registered subject DN authenticates the RP
// only when it carries a key of that JWK Set.
func TestAutomaticRegistrationTLSClientAuthRequiresRPKey(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI, map[string]any{
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "tls_client_auth"},
		"tls_client_auth_subject_dn":            "CN=rp",
	})
	subject := func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "rp"} }
	rpKeyCert := selfSignedTestClientCertForKey(t, f.rpOIDCKey, subject)
	otherKeyCert := selfSignedTestClientCertWithSAN(t, subject)
	roots := x509.NewCertPool()
	roots.AddCert(rpKeyCert)
	roots.AddCert(otherKeyCert)
	srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.ClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
		deps.ClientCertificateTrust = server.TrustedClientCAs{Roots: roots, Revocation: server.NoClientCertificateRevocationCheck{}}
	})
	if err := requestClientCredentialsWithCertificate(t, srv, f, rpKeyCert); err != nil {
		t.Fatalf("certificate carrying the RP's key: %v, want a token", err)
	}
	if code := serverErrorCode(t, requestClientCredentialsWithCertificate(t, srv, f, otherKeyCert)); code != server.ErrorInvalidClient {
		t.Fatalf("certificate carrying another key: error code %q, want %q", code, server.ErrorInvalidClient)
	}
}

// TestAutomaticRegistrationSelfSignedAcceptsEveryX5C covers §12.1.1.2's
// "an x5c Claim for a key in the Entity's RP JWK Set": the certificate
// of the second key authenticates the RP as the first's does, as during
// a key rollover.
func TestAutomaticRegistrationSelfSignedAcceptsEveryX5C(t *testing.T) {
	first, second := generateKey(t), generateKey(t)
	firstCert := selfSignedTestClientCertForKey(t, first, func(*x509.Certificate) {})
	secondCert := selfSignedTestClientCertForKey(t, second, func(*x509.Certificate) {})
	f := setupAutomaticRegistrationFixture(t, testRedirectURI, map[string]any{
		"token_endpoint_auth_method": "self_signed_tls_client_auth",
		"jwks":                       jwksWithCertificates(t, map[string]*ecdsa.PrivateKey{"one": first, "two": second}, map[string]*x509.Certificate{"one": firstCert, "two": secondCert}),
	})
	srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.ClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowedClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodSelfSignedTLSClientAuth}
	})
	for name, cert := range map[string]*x509.Certificate{"first": firstCert, "second": secondCert} {
		if err := requestClientCredentialsWithCertificate(t, srv, f, cert); err != nil {
			t.Errorf("the %s key's certificate: %v, want a token", name, err)
		}
	}
	if code := serverErrorCode(t, requestClientCredentialsWithCertificate(t, srv, f, selfSignedTestClientCertWithSAN(t, func(*x509.Certificate) {}))); code != server.ErrorInvalidClient {
		t.Fatalf("an unpublished certificate: error code %q, want %q", code, server.ErrorInvalidClient)
	}
}

func jwksWithCertificates(t *testing.T, keys map[string]*ecdsa.PrivateKey, certs map[string]*x509.Certificate) json.RawMessage {
	t.Helper()
	var entries []json.RawMessage
	for kid, key := range keys {
		jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jwk.WithKeyID(kid).MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["x5c"] = []string{base64.StdEncoding.EncodeToString(certs[kid].Raw)}
		entry, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	body, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
