package payroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Alder Bank's PKI for its API clients' certificates: a root CA, which
// only issues and revokes issuing CAs, and the issuing CAs below it. It's
// not the demo CA a browser is told to trust: that one serves the demo's
// pages and can only vouch for *.localhost.
const (
	rootCAName = "Alder Bank root CA"
	// clientCAName issues client certificates today.
	clientCAName = "Alder Bank client CA 2"
	// retiredCAName issued them before; its key leaked, and the root
	// revoked it.
	retiredCAName = "Alder Bank client CA 1"
)

const (
	certificateLifetime = 90 * 24 * time.Hour
	// crlLifetime is how long each CRL the bank publishes is current
	// for (its nextUpdate). The bank signs a new one before that, and
	// whenever it revokes a certificate.
	crlLifetime = time.Hour
)

// The subject names Alder Bank registered each client under
// (tls_client_auth_subject_dn).
var (
	ledgerlineSubject  = pkix.Name{Organization: []string{"Ledgerline Ltd"}, OrganizationalUnit: []string{"Payroll API"}, CommonName: "ledgerline-payroll"}
	copperfieldSubject = pkix.Name{Organization: []string{"Copperfield Payroll Ltd"}, CommonName: "copperfield-payroll"}
)

// pki is a certificate authority that issues TLS client certificates
// and publishes a certificate revocation list (CRL).
type pki struct {
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool

	mu      sync.Mutex
	revoked []x509.RevocationListEntry
	crl     *x509.RevocationList
	number  int64
}

// newPKI is a root CA named name, which may issue one level of issuing
// CAs (subordinate).
func newPKI(name string, now time.Time) (*pki, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template, err := caTemplate(name, now)
	if err != nil {
		return nil, err
	}
	template.MaxPathLen = 1
	return newCA(template, template, key, key)
}

// subordinate is an issuing CA named name that p issues: it signs client
// certificates, not further CAs.
func (p *pki) subordinate(name string, now time.Time) (*pki, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template, err := caTemplate(name, now)
	if err != nil {
		return nil, err
	}
	template.MaxPathLenZero = true
	return newCA(template, p.ca, key, p.key)
}

func caTemplate(name string, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{Organization: []string{"Alder Bank"}, CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}, nil
}

// newCA signs template with parentKey as parent, for key.
func newCA(template, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) (*pki, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca: ca, key: key, pool: pool}, nil
}

// issue signs a TLS client certificate for subject, valid from
// notBefore until notAfter.
func (p *pki) issue(subject pkix.Name, notBefore, notAfter time.Time) (*tls.Certificate, error) {
	return newClientCertificate(subject, notBefore, notAfter, func(template *x509.Certificate, key *ecdsa.PrivateKey) ([]byte, error) {
		return x509.CreateCertificate(rand.Reader, template, p.ca, &key.PublicKey, p.key)
	})
}

// newBankPKI builds Alder Bank's root CA and its two issuing CAs, the
// retired one already revoked by the root.
func (w *World) newBankPKI(now time.Time) error {
	var err error
	if w.rootCA, err = newPKI(rootCAName, now); err != nil {
		return err
	}
	if w.clientCA, err = w.rootCA.subordinate(clientCAName, now); err != nil {
		return err
	}
	if w.retiredCA, err = w.rootCA.subordinate(retiredCAName, now); err != nil {
		return err
	}
	w.rootCA.revoke(w.retiredCA.ca, now.Add(-time.Hour))
	return nil
}

// selfSigned is a TLS client certificate for subject that signs itself:
// anyone can make one, with any subject.
func selfSigned(subject pkix.Name, now time.Time) (*tls.Certificate, error) {
	return newClientCertificate(subject, now.Add(-time.Hour), now.Add(certificateLifetime), func(template *x509.Certificate, key *ecdsa.PrivateKey) ([]byte, error) {
		return x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	})
}

// newClientCertificate generates a key and has sign sign a TLS client
// certificate for it.
func newClientCertificate(subject pkix.Name, notBefore, notAfter time.Time, sign func(template *x509.Certificate, key *ecdsa.PrivateKey) ([]byte, error)) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	der, err := sign(&x509.Certificate{
		SerialNumber: serial, Subject: subject, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// revoke adds cert to the CRL from at.
func (p *pki) revoke(cert *x509.Certificate, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: at})
	p.crl = nil
}

// currentCRL is p's current CRL. A real deployment would fetch and cache
// each CA's published list; here the CAs are in the same process, so
// each signs a fresh one whenever its last is close to its nextUpdate or
// it has revoked a certificate since.
func (p *pki) currentCRL() (*x509.RevocationList, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.crl != nil && now.Before(p.crl.NextUpdate.Add(-crlLifetime/4)) {
		return p.crl, nil
	}
	p.number++
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(p.number), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(crlLifetime),
		RevokedCertificateEntries: p.revoked,
	}, p.ca, p.key)
	if err != nil {
		return nil, fmt.Errorf("sign CRL: %w", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	p.crl = crl
	return crl, nil
}

// currentCRLs is every CRL Alder Bank's authorization server checks
// client certificates against (server.ClientCertificateCRLs.Lists): one
// from each CA that issues a certificate in a chain. The root's revokes
// issuing CAs, the issuing CAs' revoke client certificates.
func (w *World) currentCRLs(context.Context) ([]*x509.RevocationList, error) {
	var lists []*x509.RevocationList
	for _, ca := range []*pki{w.rootCA, w.clientCA, w.retiredCA} {
		crl, err := ca.currentCRL()
		if err != nil {
			return nil, err
		}
		lists = append(lists, crl)
	}
	return lists, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// thumbprint is a certificate's RFC 8705 §3.1 "x5t#S256": what an access
// token bound to it carries in its cnf claim.
func thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// certificates is every client certificate the demo uses.
type certificates struct {
	// ledgerline is Ledgerline's certificate, until the rotation panel
	// replaces it.
	ledgerline *tls.Certificate
	// leaked is an earlier certificate of Ledgerline's whose key leaked:
	// the bank revoked it.
	leaked *tls.Certificate
	// expired is a certificate of Ledgerline's that has run out.
	expired *tls.Certificate
	// copperfield is Copperfield Payroll's certificate: another of the
	// bank's API clients, with a valid certificate of its own.
	copperfield *tls.Certificate
	// selfSigned names Ledgerline as its subject, and signs itself.
	selfSigned *tls.Certificate
	// impostor names Ledgerline as its subject, issued by a CA calling
	// itself Alder Bank's.
	impostor *tls.Certificate
	// retired names Ledgerline as its subject, minted with the retired
	// issuing CA's leaked key after the root revoked that CA.
	retired *tls.Certificate
}

func (w *World) issueCertificates(now time.Time) (certificates, error) {
	var c certificates
	var err error
	valid := func(subject pkix.Name) (*tls.Certificate, error) {
		return w.clientCA.issue(subject, now.Add(-time.Hour), now.Add(certificateLifetime))
	}
	if c.ledgerline, err = valid(ledgerlineSubject); err != nil {
		return certificates{}, err
	}
	if c.leaked, err = valid(ledgerlineSubject); err != nil {
		return certificates{}, err
	}
	w.clientCA.revoke(c.leaked.Leaf, now.Add(-time.Hour))
	if c.expired, err = w.clientCA.issue(ledgerlineSubject, now.Add(-certificateLifetime-24*time.Hour), now.Add(-24*time.Hour)); err != nil {
		return certificates{}, err
	}
	if c.copperfield, err = valid(copperfieldSubject); err != nil {
		return certificates{}, err
	}
	if c.selfSigned, err = selfSigned(ledgerlineSubject, now); err != nil {
		return certificates{}, err
	}
	if c.retired, err = w.retiredCA.issue(ledgerlineSubject, now.Add(-time.Minute), now.Add(certificateLifetime)); err != nil {
		return certificates{}, err
	}
	impostorCA, err := newPKI(clientCAName, now)
	if err != nil {
		return certificates{}, err
	}
	if c.impostor, err = impostorCA.issue(ledgerlineSubject, now.Add(-time.Hour), now.Add(certificateLifetime)); err != nil {
		return certificates{}, err
	}
	return c, nil
}
