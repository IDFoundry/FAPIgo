package demonet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Files kept in the state directory. ca.pem is the one a browser is told
// to trust.
const (
	caCertFile   = "ca.pem"
	caKeyFile    = "ca-key.pem"
	leafCertFile = "cert.pem"
	leafKeyFile  = "key.pem"
)

const (
	caLifetime   = 365 * 24 * time.Hour
	leafLifetime = 90 * 24 * time.Hour
	// renewBefore replaces a certificate this close to expiring rather
	// than let it lapse mid-demo.
	renewBefore = 30 * 24 * time.Hour
)

// certificates is the demo CA and the serving certificate it issued.
type certificates struct {
	ca      *x509.Certificate
	caKey   crypto.Signer
	serving tls.Certificate
}

// loadOrIssue returns the CA and serving certificate kept in dir, issuing
// and saving whichever is missing, expiring soon, or (for the serving
// certificate) no longer covers hosts. An empty dir keeps nothing: both
// are issued afresh.
func loadOrIssue(dir string, hosts []string, now time.Time) (certificates, error) {
	var c certificates
	var err error
	if c.ca, c.caKey, err = loadCA(dir, now); err != nil {
		if c.ca, c.caKey, err = issueCA(now); err != nil {
			return certificates{}, err
		}
		if err := save(dir, caCertFile, caKeyFile, c.ca.Raw, c.caKey); err != nil {
			return certificates{}, err
		}
	}
	if c.serving, err = loadLeaf(dir, c.ca, hosts, now); err != nil {
		if c.serving, err = issueLeaf(c.ca, c.caKey, hosts, now); err != nil {
			return certificates{}, err
		}
		if err := save(dir, leafCertFile, leafKeyFile, c.serving.Certificate[0], c.serving.PrivateKey.(crypto.Signer)); err != nil {
			return certificates{}, err
		}
	}
	return c, nil
}

func issueCA(now time.Time) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Meridian Union demo CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		// Someone who trusts this CA is trusting a key kept in a local
		// directory, so it can only vouch for *.localhost: never a real
		// site, and never an IP address.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"localhost"},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func issueLeaf(ca *x509.Certificate, caKey crypto.Signer, hosts []string, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// loadCA loads dir's CA, failing if there is none or it expires soon.
func loadCA(dir string, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	if dir == "" {
		return nil, nil, errors.New("no state directory")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, caCertFile), filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || !pair.Leaf.IsCA || now.Add(renewBefore).After(pair.Leaf.NotAfter) {
		return nil, nil, errors.New("unusable CA")
	}
	return pair.Leaf, signer, nil
}

// loadLeaf loads dir's serving certificate, failing if there is none, it
// expires soon, it wasn't issued by ca, or it doesn't cover exactly
// hosts.
func loadLeaf(dir string, ca *x509.Certificate, hosts []string, now time.Time) (tls.Certificate, error) {
	if dir == "" {
		return tls.Certificate{}, errors.New("no state directory")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, leafCertFile), filepath.Join(dir, leafKeyFile))
	if err != nil {
		return tls.Certificate{}, err
	}
	if pair.Leaf.CheckSignatureFrom(ca) != nil || now.Add(renewBefore).After(pair.Leaf.NotAfter) ||
		!slices.Equal(sorted(pair.Leaf.DNSNames), sorted(hosts)) {
		return tls.Certificate{}, errors.New("unusable serving certificate")
	}
	return pair, nil
}

// save writes a certificate and its key to dir, readable only by the
// current user. An empty dir saves nothing.
func save(dir, certFile, keyFile string, der []byte, key crypto.Signer) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// spkiHash is the base64 SHA-256 of cert's public key, the form Chrome's
// --ignore-certificate-errors-spki-list takes.
func spkiHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
