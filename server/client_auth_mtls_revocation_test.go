package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// revocationCA is a throwaway CA that can sign client certificates and
// CRLs, valid over [notBefore, notAfter].
type revocationCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newRevocationCA(t *testing.T, name string, notBefore, notAfter time.Time) revocationCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return revocationCA{cert: cert, key: key, pool: pool}
}

// issue signs a client certificate valid over [notBefore, notAfter].
func (ca revocationCA) issue(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	return caSignedTestClientCertWithSAN(t, ca.cert, ca.key, func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = notBefore, notAfter
	})
}

// crl signs a CRL valid over [thisUpdate, nextUpdate] listing revoked.
func (ca revocationCA) crl(t *testing.T, thisUpdate, nextUpdate time.Time, extensions []pkix.Extension, revoked ...*x509.Certificate) *x509.RevocationList {
	t.Helper()
	template := &x509.RevocationList{
		Number:          big.NewInt(1),
		ThisUpdate:      thisUpdate,
		NextUpdate:      nextUpdate,
		ExtraExtensions: extensions,
	}
	for _, cert := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: thisUpdate,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	return list
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	return serial
}

func staticCRLs(lists ...*x509.RevocationList) server.ClientCertificateCRLs {
	return server.ClientCertificateCRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		return lists, nil
	}}
}

// pushWithCertificate authenticates cert at the PAR endpoint of a
// ClientAuthMethodTLSClientAuth client registered for cert's subject.
func pushWithCertificate(t *testing.T, cert *x509.Certificate, trust server.ClientCertificateTrust, now time.Time) error {
	t.Helper()
	h := newHarnessWithClientAuthTLSSubjectDNAndTrust(t, cert.Subject.String(), trust, now)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: cert,
	})
	return err
}

func wantInvalidClient(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("PushAuthorizationRequest = nil error, want invalid_client")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

// TestTLSClientAuthChecksValidityAtServerClock checks that a client
// certificate's validity period is judged at Dependencies.Clock's time,
// not the wall clock's.
func TestTLSClientAuthChecksValidityAtServerClock(t *testing.T) {
	wall := time.Now()
	ca := newRevocationCA(t, "clock-ca", wall.Add(-48*time.Hour), wall.Add(48*time.Hour))
	trust := server.TrustedClientCAs{Roots: ca.pool, Revocation: server.NoClientCertificateRevocationCheck{}}

	t.Run("valid now, expired at the server's clock", func(t *testing.T) {
		cert := ca.issue(t, wall.Add(-time.Hour), wall.Add(time.Hour))
		wantInvalidClient(t, pushWithCertificate(t, cert, trust, wall.Add(2*time.Hour)))
	})
	t.Run("expired now, valid at the server's clock", func(t *testing.T) {
		cert := ca.issue(t, wall.Add(-3*time.Hour), wall.Add(-time.Hour))
		if err := pushWithCertificate(t, cert, trust, wall.Add(-2*time.Hour)); err != nil {
			t.Fatalf("PushAuthorizationRequest: %v", err)
		}
	})
}

type recordingRevocation struct {
	err    error
	checks []server.ClientCertificateRevocationCheck
}

func (r *recordingRevocation) CheckRevocation(_ context.Context, check server.ClientCertificateRevocationCheck) error {
	r.checks = append(r.checks, check)
	return r.err
}

func TestTLSClientAuthConsultsRevocation(t *testing.T) {
	now := time.Now()
	ca := newRevocationCA(t, "hook-ca", now.Add(-time.Hour), now.Add(time.Hour))
	cert := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))

	t.Run("not revoked", func(t *testing.T) {
		rev := &recordingRevocation{}
		if err := pushWithCertificate(t, cert, server.TrustedClientCAs{Roots: ca.pool, Revocation: rev}, now); err != nil {
			t.Fatalf("PushAuthorizationRequest: %v", err)
		}
		if len(rev.checks) != 1 {
			t.Fatalf("CheckRevocation called %d times, want 1", len(rev.checks))
		}
		check := rev.checks[0]
		if len(check.Chain) != 2 || !check.Chain[0].Equal(cert) || !check.Chain[1].Equal(ca.cert) {
			t.Fatalf("CheckRevocation chain = %d certificates, want [leaf, CA]", len(check.Chain))
		}
		if !check.Now.Equal(now) {
			t.Fatalf("CheckRevocation Now = %v, want the server clock's %v", check.Now, now)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		rev := &recordingRevocation{err: errors.New("revoked")}
		wantInvalidClient(t, pushWithCertificate(t, cert, server.TrustedClientCAs{Roots: ca.pool, Revocation: rev}, now))
	})
	t.Run("not consulted for an untrusted chain", func(t *testing.T) {
		rev := &recordingRevocation{}
		wantInvalidClient(t, pushWithCertificate(t, selfSignedTestClientCert(t), server.TrustedClientCAs{Roots: ca.pool, Revocation: rev}, now))
		if len(rev.checks) != 0 {
			t.Fatalf("CheckRevocation called %d times for an untrusted chain, want 0", len(rev.checks))
		}
	})
}

func TestTLSClientAuthWithClientCertificateCRLs(t *testing.T) {
	now := time.Now()
	ca := newRevocationCA(t, "crl-ca", now.Add(-time.Hour), now.Add(time.Hour))
	cert := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	other := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	trust := func(lists ...*x509.RevocationList) server.TrustedClientCAs {
		return server.TrustedClientCAs{Roots: ca.pool, Revocation: staticCRLs(lists...)}
	}

	if err := pushWithCertificate(t, cert, trust(ca.crl(t, now.Add(-time.Minute), now.Add(time.Hour), nil, other)), now); err != nil {
		t.Fatalf("PushAuthorizationRequest(another certificate revoked): %v", err)
	}
	wantInvalidClient(t, pushWithCertificate(t, cert, trust(ca.crl(t, now.Add(-time.Minute), now.Add(time.Hour), nil, cert)), now))
}

func TestClientCertificateCRLs(t *testing.T) {
	now := time.Now()
	ca := newRevocationCA(t, "crl-ca", now.Add(-time.Hour), now.Add(time.Hour))
	// Same name as ca, different key: its CRLs mustn't count as ca's.
	impostor := newRevocationCA(t, "crl-ca", now.Add(-time.Hour), now.Add(time.Hour))
	cert := ca.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	chain := []*x509.Certificate{cert, ca.cert}
	current := func(extensions []pkix.Extension, revoked ...*x509.Certificate) *x509.RevocationList {
		return ca.crl(t, now.Add(-time.Minute), now.Add(time.Hour), extensions, revoked...)
	}
	deltaIndicator := []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{0x02, 0x01, 0x01}}}

	cases := []struct {
		name    string
		lists   []*x509.RevocationList
		wantErr string
	}{
		{name: "not revoked", lists: []*x509.RevocationList{current(nil)}},
		{name: "revoked", lists: []*x509.RevocationList{current(nil, cert)}, wantErr: "is revoked"},
		{name: "revoked in one of several current lists", lists: []*x509.RevocationList{current(nil), current(nil, cert)}, wantErr: "is revoked"},
		{name: "no list", wantErr: "no current CRL"},
		{name: "stale", lists: []*x509.RevocationList{ca.crl(t, now.Add(-2*time.Hour), now.Add(-time.Hour), nil)}, wantErr: "no current CRL"},
		{name: "not yet valid", lists: []*x509.RevocationList{ca.crl(t, now.Add(time.Minute), now.Add(time.Hour), nil)}, wantErr: "no current CRL"},
		{name: "signed by a same-named impostor", lists: []*x509.RevocationList{impostor.crl(t, now.Add(-time.Minute), now.Add(time.Hour), nil)}, wantErr: "no current CRL"},
		{name: "delta CRL only", lists: []*x509.RevocationList{current(deltaIndicator)}, wantErr: "no current CRL"},
		{name: "nil list ignored", lists: []*x509.RevocationList{nil, current(nil)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := staticCRLs(tc.lists...).CheckRevocation(context.Background(), server.ClientCertificateRevocationCheck{Chain: chain, Now: now})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckRevocation: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CheckRevocation = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("lists error", func(t *testing.T) {
		crls := server.ClientCertificateCRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
			return nil, errors.New("CRL cache empty")
		}}
		if err := crls.CheckRevocation(context.Background(), server.ClientCertificateRevocationCheck{Chain: chain, Now: now}); err == nil {
			t.Fatal("CheckRevocation = nil error, want the Lists error")
		}
	})
}

func TestNewRejectsIncompleteTrustedClientCAs(t *testing.T) {
	pool := x509.NewCertPool()
	cases := map[string]server.TrustedClientCAs{
		"nil roots":      {Revocation: server.NoClientCertificateRevocationCheck{}},
		"nil revocation": {Roots: pool},
		"nil CRL lists":  {Roots: pool, Revocation: server.ClientCertificateCRLs{}},
	}
	for name, trust := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies()
			deps.ClientCertificateTrust = trust
			if _, err := server.New(validConfig(t), deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
	deps := validDependencies()
	deps.ClientCertificateTrust = server.TrustedClientCAs{Roots: pool, Revocation: staticCRLs()}
	if _, err := server.New(validConfig(t), deps); err != nil {
		t.Fatalf("New(complete TrustedClientCAs): %v", err)
	}
}
