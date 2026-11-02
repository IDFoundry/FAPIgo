package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// testCert is a certificate and its private key, for building attester
// PKIs in tests.
type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

type certOptions struct {
	parent             *testCert // nil: self-signed
	isCA               bool
	notBefore          time.Time
	notAfter           time.Time
	keyUsage           x509.KeyUsage
	key                crypto.Signer // nil: fresh P-256
	uris               []string      // URI subject alternative names
	extKeyUsage        []x509.ExtKeyUsage
	unknownExtKeyUsage []asn1.ObjectIdentifier
}

var testSerial int64

func newTestCert(t *testing.T, name string, o certOptions) testCert {
	t.Helper()
	key := o.key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		key = k
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(24 * time.Hour)
	}
	if o.keyUsage == 0 {
		o.keyUsage = x509.KeyUsageDigitalSignature
		if o.isCA {
			o.keyUsage |= x509.KeyUsageCertSign
		}
	}
	testSerial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(testSerial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		KeyUsage:              o.keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
		ExtKeyUsage:           o.extKeyUsage,
		UnknownExtKeyUsage:    o.unknownExtKeyUsage,
	}
	for _, raw := range o.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse SAN URI %q: %v", raw, err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	parentCert, parentKey := tmpl, key
	if o.parent != nil {
		parentCert, parentKey = o.parent.cert, o.parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create certificate %s: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", name, err)
	}
	return testCert{cert: cert, key: key}
}

func x5cOf(certs ...testCert) json.RawMessage {
	entries := make([]string, len(certs))
	for i, c := range certs {
		entries[i] = base64.StdEncoding.EncodeToString(c.cert.Raw)
	}
	raw, _ := json.Marshal(entries)
	return raw
}

func poolOf(certs ...testCert) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c.cert)
	}
	return pool
}

// createX5CAttestation signs a client attestation for testClientID with
// signer, carrying x5c (and kid, if non-empty) in its header.
func createX5CAttestation(t *testing.T, signer crypto.Signer, x5c json.RawMessage, kid string, instancePub *ecdsa.PublicKey, now time.Time) string {
	t.Helper()
	jwk, err := jose.NewJWK(instancePub, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": testAttesterIssuer,
		"sub": testClientID.String(),
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(jwkJSON)},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(signer, jose.Header{Algorithm: fapi.ES256, Type: clientattestation.TypHeader, KeyID: kid, X5C: x5c}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// requestWithAttestation runs a client_credentials request authenticated
// by attestation, returning its error.
func requestWithAttestation(t *testing.T, h harness, attestation string, instanceKey *ecdsa.PrivateKey) error {
	t.Helper()
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-x5c", h.now)
	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:                  server.FormRequest{Parameters: attestationClientCredentialsFormParams("accounts")},
		ClientAttestations:    []string{attestation},
		ClientAttestationPoPs: []string{pop},
		DPoPProofs:            []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	return err
}

func TestX5CAttesterChainAcceptsChainToTrustAnchor(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	intermediate := newTestCert(t, "intermediate", certOptions{parent: &root, isCA: true})
	leafFromRoot := newTestCert(t, "attester", certOptions{parent: &root})
	leafFromIntermediate := newTestCert(t, "attester", certOptions{parent: &intermediate})

	cases := map[string]struct {
		leaf testCert
		x5c  json.RawMessage
		kid  string
	}{
		"leaf issued by the anchor":    {leafFromRoot, x5cOf(leafFromRoot), ""},
		"leaf through an intermediate": {leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate), ""},
		"kid present but ignored":      {leafFromRoot, x5cOf(leafFromRoot), "not-a-registered-key"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(root)}, IssuerBinding: server.AttesterIssuerByTrustAnchors})
			instanceKey := generateKey(t)
			attestation := createX5CAttestation(t, tc.leaf.key, tc.x5c, tc.kid, &instanceKey.PublicKey, h.now)
			if err := requestWithAttestation(t, h, attestation, instanceKey); err != nil {
				t.Fatalf("RequestClientCredentialsToken: %v", err)
			}
		})
	}
}

func TestX5CAttesterChainRejectsUntrustedAttestation(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	otherRoot := newTestCert(t, "other root", certOptions{isCA: true})
	leaf := newTestCert(t, "attester", certOptions{parent: &root})
	selfSigned := newTestCert(t, "self-signed attester", certOptions{})
	fromOtherRoot := newTestCert(t, "attester", certOptions{parent: &otherRoot})
	notSigning := newTestCert(t, "attester", certOptions{parent: &root, keyUsage: x509.KeyUsageKeyEncipherment})
	caLeaf := newTestCert(t, "attester CA", certOptions{parent: &root, isCA: true})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rsaLeaf := newTestCert(t, "rsa attester", certOptions{parent: &root, key: rsaKey})
	otherSigner := generateKey(t)

	cases := map[string]struct {
		signer crypto.Signer
		x5c    json.RawMessage
		roots  *x509.CertPool
	}{
		"no x5c":                           {leaf.key, nil, poolOf(root)},
		"chain to an untrusted anchor":     {fromOtherRoot.key, x5cOf(fromOtherRoot), poolOf(root)},
		"self-signed leaf that is anchor":  {selfSigned.key, x5cOf(selfSigned), poolOf(root, selfSigned)},
		"leaf without digitalSignature":    {notSigning.key, x5cOf(notSigning), poolOf(root)},
		"CA certificate as the leaf":       {caLeaf.key, x5cOf(caLeaf), poolOf(root)},
		"RSA leaf for an ES256 client":     {otherSigner, x5cOf(rsaLeaf), poolOf(root)},
		"signed by a key other than leaf":  {otherSigner, x5cOf(leaf), poolOf(root)},
		"x5c not an array":                 {leaf.key, json.RawMessage(`"MIIB"`), poolOf(root)},
		"x5c empty":                        {leaf.key, json.RawMessage(`[]`), poolOf(root)},
		"x5c not base64":                   {leaf.key, json.RawMessage(`["!!"]`), poolOf(root)},
		"x5c not a certificate":            {leaf.key, json.RawMessage(`["AAAA"]`), poolOf(root)},
		"x5c url-safe base64 not standard": {leaf.key, urlSafeX5C(leaf), poolOf(root)},
		"x5c over the length limit":        {leaf.key, x5cRepeated(leaf, clientattestation.MaxCertificateChainLength+1), poolOf(root)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: tc.roots}, IssuerBinding: server.AttesterIssuerByTrustAnchors})
			instanceKey := generateKey(t)
			attestation := createX5CAttestation(t, tc.signer, tc.x5c, "", &instanceKey.PublicKey, h.now)
			err := requestWithAttestation(t, h, attestation, instanceKey)
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q (err %v)", code, server.ErrorInvalidClient, err)
			}
		})
	}
}

// TestX5CAttesterChainRefusesAnchorInX5C covers HAIP 1.0 keeping the
// trust anchor out of x5c: a self-signed certificate below the leaf,
// configured as an anchor or not, and a configured anchor that is not
// self-signed (an intermediate trusted directly), under both a
// TrustAnchors pool and AttesterIssuerBoundToAnchor, are refused, while
// the leaf alone or with its intermediates is accepted.
func TestX5CAttesterChainRefusesAnchorInX5C(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	intermediate := newTestCert(t, "intermediate", certOptions{parent: &root, isCA: true})
	stray := newTestCert(t, "unrelated self-signed", certOptions{isCA: true})
	san := []string{testAttesterIssuer}
	leafFromRoot := newTestCert(t, "attester", certOptions{parent: &root, uris: san})
	leafFromIntermediate := newTestCert(t, "attester", certOptions{parent: &intermediate, uris: san})

	pool := func(anchors ...testCert) server.AttesterTrust {
		return server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(anchors...)}, IssuerBinding: server.AttesterIssuerByTrustAnchors}
	}
	bound := func(anchors ...testCert) server.AttesterTrust {
		list := make(server.StaticAttesterAnchors, len(anchors))
		for i, a := range anchors {
			list[i] = server.AttesterAnchor{Certificate: a.cert, Issuers: []string{testAttesterIssuer}}
		}
		return boundChain(list)
	}
	for name, tc := range map[string]struct {
		trust  server.AttesterTrust
		leaf   attesterLeaf
		wantOK bool
	}{
		"leaf, intermediate, root":                      {pool(root), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate, root)}, false},
		"leaf, root":                                    {pool(root), attesterLeaf{leafFromRoot, x5cOf(leafFromRoot, root)}, false},
		"leaf, root, bound":                             {bound(root), attesterLeaf{leafFromRoot, x5cOf(leafFromRoot, root)}, false},
		"intermediate anchor in x5c, pool":              {pool(intermediate), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate)}, false},
		"intermediate anchor in x5c, bound":             {bound(intermediate), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate)}, false},
		"intermediate anchor in x5c, root also anchor":  {pool(root, intermediate), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate)}, false},
		"self-signed certificate that is not an anchor": {pool(root), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate, stray)}, false},
		"leaf, intermediate":                            {pool(root), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate)}, true},
		"leaf, intermediate, bound":                     {bound(root), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate, intermediate)}, true},
		"leaf directly under the anchor":                {pool(root), attesterLeaf{leafFromRoot, x5cOf(leafFromRoot)}, true},
		"leaf directly under an intermediate anchor":    {bound(intermediate), attesterLeaf{leafFromIntermediate, x5cOf(leafFromIntermediate)}, true},
	} {
		t.Run(name, func(t *testing.T) {
			checkAttesterLeaf(t, newHarnessWithAttesterTrust(t, nil, tc.trust), tc.leaf, tc.wantOK)
		})
	}
}

// TestX5CAttesterChainRefusesReissuedAnchorInX5C covers an anchor that
// is not self-signed (an intermediate trusted directly) reaching x5c as
// another certificate for the same subject and key: re-issued by the
// anchor's own parent, or cross-signed by an unrelated root. Either
// copy is the anchor, so HAIP 1.0 keeps it out of x5c just as it does
// the configured certificate itself.
func TestX5CAttesterChainRefusesReissuedAnchorInX5C(t *testing.T) {
	root := newTestCert(t, "offline root", certOptions{isCA: true})
	anchor := newTestCert(t, "attester CA", certOptions{parent: &root, isCA: true})
	reissued := newTestCert(t, "attester CA", certOptions{parent: &root, isCA: true, key: anchor.key})
	otherRoot := newTestCert(t, "other root", certOptions{isCA: true})
	crossSigned := newTestCert(t, "attester CA", certOptions{parent: &otherRoot, isCA: true, key: anchor.key})
	otherKey := newTestCert(t, "attester CA", certOptions{parent: &root, isCA: true})
	leaf := newTestCert(t, "attester", certOptions{parent: &anchor})
	for name, tc := range map[string]struct {
		x5c    json.RawMessage
		wantOK bool
	}{
		"anchor itself":                     {x5cOf(leaf, anchor), false},
		"anchor re-issued by its parent":    {x5cOf(leaf, reissued), false},
		"anchor cross-signed by other root": {x5cOf(leaf, crossSigned), false},
		"same subject, another key":         {x5cOf(leaf, otherKey), true},
		"leaf alone":                        {x5cOf(leaf), true},
	} {
		t.Run(name, func(t *testing.T) {
			checkAttesterLeaf(t, leafPolicyHarness(t, anchor, nil), attesterLeaf{leaf, tc.x5c}, tc.wantOK)
		})
	}
}

// TestX5CAttesterChainChecksValidityAtServerClock covers certificate
// validity being judged at the server's injected Clock, not the wall
// clock. The server's clock is set a month in the past, so each case
// only comes out right if the injected time is the one used.
func TestX5CAttesterChainChecksValidityAtServerClock(t *testing.T) {
	wallNow := time.Now()
	serverNow := wallNow.Add(-30 * 24 * time.Hour)
	root := newTestCert(t, "root", certOptions{isCA: true, notBefore: serverNow.Add(-24 * time.Hour), notAfter: wallNow.Add(24 * time.Hour)})

	cases := map[string]struct {
		leaf   testCert
		wantOK bool
	}{
		"valid at server clock, expired by wall clock": {
			newTestCert(t, "attester", certOptions{parent: &root, notBefore: serverNow.Add(-time.Hour), notAfter: serverNow.Add(time.Hour)}), true,
		},
		"valid by wall clock, not yet valid at server clock": {
			newTestCert(t, "attester", certOptions{parent: &root, notBefore: wallNow.Add(-time.Hour), notAfter: wallNow.Add(time.Hour)}), false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrustAt(t, serverNow, nil, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(root)}, IssuerBinding: server.AttesterIssuerByTrustAnchors})
			instanceKey := generateKey(t)
			attestation := createX5CAttestation(t, tc.leaf.key, x5cOf(tc.leaf), "", &instanceKey.PublicKey, h.now)
			err := requestWithAttestation(t, h, attestation, instanceKey)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

// clientAnchors is an AttesterTrustAnchors keyed by client ID, the way a
// deployment would scope accepted Wallet Providers per client.
type clientAnchors struct {
	pools map[fapi.ClientID]*x509.CertPool
	err   error
}

func (c clientAnchors) TrustAnchors(_ context.Context, client storage.RegisteredClient) (*x509.CertPool, error) {
	return c.pools[client.ID()], c.err
}

func TestX5CAttesterChainUsesPerClientTrustAnchors(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	otherRoot := newTestCert(t, "other root", certOptions{isCA: true})
	leaf := newTestCert(t, "attester", certOptions{parent: &root})

	cases := map[string]struct {
		anchors clientAnchors
		wantOK  bool
	}{
		"anchor configured for this client":    {clientAnchors{pools: map[fapi.ClientID]*x509.CertPool{testClientID: poolOf(root)}}, true},
		"anchor configured for another client": {clientAnchors{pools: map[fapi.ClientID]*x509.CertPool{testClientID: poolOf(otherRoot), "other-client": poolOf(root)}}, false},
		"no anchors for this client":           {clientAnchors{pools: map[fapi.ClientID]*x509.CertPool{}}, false},
		"anchor source fails":                  {clientAnchors{pools: map[fapi.ClientID]*x509.CertPool{testClientID: poolOf(root)}, err: errors.New("trust list unavailable")}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: tc.anchors, IssuerBinding: server.AttesterIssuerByTrustAnchors})
			instanceKey := generateKey(t)
			attestation := createX5CAttestation(t, leaf.key, x5cOf(leaf), "", &instanceKey.PublicKey, h.now)
			err := requestWithAttestation(t, h, attestation, instanceKey)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

// TestRegisteredAttesterKeysIgnoresX5C pins today's behaviour for
// deployments that keep registered keys: an x5c the server can't verify
// against anything plays no part, and the registered key decides.
func TestRegisteredAttesterKeysIgnoresX5C(t *testing.T) {
	attesterKey := generateKey(t)
	h := newHarnessWithAttestationClientCredentials(t, attesterKey)
	instanceKey := generateKey(t)
	attestation := createX5CAttestation(t, attesterKey, json.RawMessage(`["AAAA"]`), "", &instanceKey.PublicKey, h.now)
	if err := requestWithAttestation(t, h, attestation, instanceKey); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
}

func TestNewAttesterTrustRequirements(t *testing.T) {
	cases := map[string]struct {
		enabled bool
		trust   server.AttesterTrust
		wantErr bool
	}{
		"required when attestation enabled":       {true, nil, true},
		"not required when disabled":              {false, nil, false},
		"registered keys":                         {true, server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{}}, false},
		"registered keys by pointer":              {true, &server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{}}, false},
		"registered keys without a key source":    {true, server.RegisteredAttesterKeys{}, true},
		"nil registered keys pointer":             {true, (*server.RegisteredAttesterKeys)(nil), true},
		"nil x5c chain pointer":                   {true, (*server.X5CAttesterChain)(nil), true},
		"x5c chain, issuer in certificate":        {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}, IssuerBinding: server.AttesterIssuerInCertificate}, false},
		"x5c chain, bound by trust anchors":       {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}, IssuerBinding: server.AttesterIssuerByTrustAnchors}, false},
		"x5c chain without issuer binding":        {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}}, true},
		"x5c chain with unknown issuer binding":   {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}, IssuerBinding: server.AttesterIssuerBinding(99)}, true},
		"x5c chain without trust anchors":         {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, IssuerBinding: server.AttesterIssuerInCertificate}, true},
		"x5c chain opting out of the leaf policy": {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}, IssuerBinding: server.AttesterIssuerInCertificate, LeafPolicy: server.AnyAttesterLeaf{}}, false},
		"x5c chain with nil leaf policy func":     {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}, IssuerBinding: server.AttesterIssuerInCertificate, LeafPolicy: server.AttesterLeafPolicyFunc(nil)}, true},
		"x5c chain with nil leaf policy pointer":  {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()}, IssuerBinding: server.AttesterIssuerInCertificate, LeafPolicy: (*server.DefaultAttesterLeafPolicy)(nil)}, true},
		"x5c chain with nil static anchor pool":   {true, server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{}, IssuerBinding: server.AttesterIssuerInCertificate}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			if tc.enabled {
				cfg = validAttestationConfig(t)
			}
			deps := validDependencies()
			deps.AttesterTrust = tc.trust
			_, err := server.New(cfg, deps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func urlSafeX5C(c testCert) json.RawMessage {
	raw, _ := json.Marshal([]string{strings.TrimRight(base64.URLEncoding.EncodeToString(c.cert.Raw), "=") + "-_"})
	return raw
}

func x5cRepeated(c testCert, n int) json.RawMessage {
	certs := make([]testCert, n)
	for i := range certs {
		certs[i] = c
	}
	return x5cOf(certs...)
}

// TestX5CAttesterChainIssuerInCertificate covers the impersonation
// AttesterIssuerInCertificate exists to stop: with one anchor shared by
// two attesters (a trust list, say), attester B's certificate must not
// authenticate a client registered with attester A — even though B
// writes A's identifier into the attestation's "iss".
func TestX5CAttesterChainIssuerInCertificate(t *testing.T) {
	sharedRoot := newTestCert(t, "trust list CA", certOptions{isCA: true})
	cases := map[string]struct {
		uris   []string
		wantOK bool
	}{
		"certificate names the client's attester":         {[]string{testAttesterIssuer}, true},
		"attester named among several SANs":               {[]string{"https://other.example", testAttesterIssuer}, true},
		"another attester under the same anchor":          {[]string{"https://attester-b.example.com"}, false},
		"certificate names no attester":                   {nil, false},
		"near miss: trailing slash is a different string": {[]string{testAttesterIssuer + "/"}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			leaf := newTestCert(t, "attester", certOptions{parent: &sharedRoot, uris: tc.uris})
			h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
				Revocation:    server.NoClientCertificateRevocationCheck{},
				TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(sharedRoot)},
				IssuerBinding: server.AttesterIssuerInCertificate,
			})
			instanceKey := generateKey(t)
			// "iss" is always the client's attester: the attester controls it.
			attestation := createX5CAttestation(t, leaf.key, x5cOf(leaf), "", &instanceKey.PublicKey, h.now)
			err := requestWithAttestation(t, h, attestation, instanceKey)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
			}
		})
	}
}

// TestRegisteredAttesterKeysIgnoresClientKeys proves an attestation
// verifies only against the attester's own key source: a client whose
// own key is in Dependencies.ClientKeys — as keys/ephemeral or
// federation automatic registration put it there — can't sign its own
// attestation with that key.
func TestRegisteredAttesterKeysIgnoresClientKeys(t *testing.T) {
	now := time.Now()
	clientOwnKey, attesterKey, instanceKey := generateKey(t), generateKey(t), generateKey(t)
	pop := createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", now)
	for name, tc := range map[string]struct {
		signer  *ecdsa.PrivateKey
		wantErr bool
	}{
		"signed with the client's own key": {clientOwnKey, true},
		"signed with the attester's key":   {attesterKey, false},
	} {
		t.Run(name, func(t *testing.T) {
			// ClientKeys holds clientOwnKey for testClientID.
			h := newAttestationHarness(t, now, clientOwnKey, registeredAttesterTrust(fapi.ES256, &attesterKey.PublicKey), nil)
			_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
				ClientAttestations:    []string{createAttestationHeader(t, tc.signer, testClientID.String(), &instanceKey.PublicKey, now, time.Hour)},
				ClientAttestationPoPs: []string{pop},
			})
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("AuthenticateAttestedClient: %v", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q (err %v)", code, server.ErrorInvalidClient, err)
			}
		})
	}
}

// TestRegisteredAttesterKeysUnknownAttester covers a client registered
// with an attester the key source has no keys for.
func TestRegisteredAttesterKeysUnknownAttester(t *testing.T) {
	now := time.Now()
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	trust := server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{
		"https://another-attester.example.com": {{Algorithm: fapi.ES256, PublicKey: &attesterKey.PublicKey}},
	}}
	h := newAttestationHarness(t, now, attesterKey, trust, nil)
	_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
		ClientAttestations:    []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, now, time.Hour)},
		ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q (err %v)", code, server.ErrorInvalidClient, err)
	}
}

// TestRegisteredAttesterKeysNoKeyForAlgorithm covers an attester whose
// registered keys include none for the client's attestation algorithm.
func TestRegisteredAttesterKeysNoKeyForAlgorithm(t *testing.T) {
	now := time.Now()
	attesterKey, instanceKey := generateKey(t), generateKey(t)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	trust := server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{
		testAttesterIssuer: {{Algorithm: fapi.EdDSA, PublicKey: edPub}},
	}}
	h := newAttestationHarness(t, now, attesterKey, trust, nil)
	_, err = h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
		ClientAttestations:    []string{createAttestationHeader(t, attesterKey, testClientID.String(), &instanceKey.PublicKey, now, time.Hour)},
		ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-1", now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q (err %v)", code, server.ErrorInvalidClient, err)
	}
}

// TestX5CAttesterChainRefusesUnboundedRSAKeys covers an x5c whose
// certificates carry RSA keys the caller chose to be costly: a modulus
// over 4096 bits or an exponent other than 65537, on the signing
// certificate or on an "intermediate" it names as its issuer. Nothing
// chains to the anchor, and the moduli were never generated, so a
// refusal from chain verification would be x509's unknown authority
// after one costly RSA operation per candidate; the key limits must
// refuse each first, without any signature check.
func TestX5CAttesterChainRefusesUnboundedRSAKeys(t *testing.T) {
	root := newTestCert(t, "trust list CA", certOptions{isCA: true})
	trust := server.X5CAttesterChain{Revocation: server.NoClientCertificateRevocationCheck{}, TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(root)}, IssuerBinding: server.AttesterIssuerInCertificate}
	// An RSA signer, so the certificates' signature algorithm is one the
	// costly RSA key would be used for.
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	for name, tc := range map[string]struct {
		bits     int
		exponent int
		onLeaf   bool
		want     error
	}{
		"31744-bit intermediate, exponent 2^31-1": {31744, 1<<31 - 1, false, jose.ErrRSAKeyTooLarge},
		"4104-bit intermediate":                   {4104, 65537, false, jose.ErrRSAKeyTooLarge},
		"intermediate with exponent 2^31-1":       {2048, 1<<31 - 1, false, jose.ErrUnsupportedRSAExponent},
		"intermediate with exponent 3":            {2048, 3, false, jose.ErrUnsupportedRSAExponent},
		"8192-bit signing certificate":            {8192, 65537, true, jose.ErrRSAKeyTooLarge},
		"signing certificate with exponent 3":     {2048, 3, true, jose.ErrUnsupportedRSAExponent},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithAttesterTrust(t, nil, trust)
			x5c, err := json.Marshal(costlyRSAX5C(t, signer, tc.bits, tc.exponent, tc.onLeaf)) // []byte marshals as standard base64
			if err != nil {
				t.Fatalf("marshal x5c: %v", err)
			}
			instanceKey := generateKey(t)
			err = requestWithAttestation(t, h, createX5CAttestation(t, generateKey(t), x5c, "", &instanceKey.PublicKey, h.now), instanceKey)
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("error code = %q, want %q (err %v)", code, server.ErrorInvalidClient, err)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want it to wrap %v (refused by the key limits, before any signature check)", err, tc.want)
			}
		})
	}
}

// costlyRSAX5C builds an attacker's x5c around an RSA public key with a
// random (never generated) modulus of the given bits and exponent,
// signed by signer:
// either as the signing certificate's own key, or as the key of an
// "intermediate" the signing certificate names as its issuer, whose
// signature is then junk as long as that modulus.
func costlyRSAX5C(t *testing.T, signer *rsa.PrivateKey, bits, exponent int, onLeaf bool) [][]byte {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	costly := &rsa.PublicKey{N: n, E: exponent}
	now := time.Now()
	issuer := pkix.Name{CommonName: "attester CA"}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "attester"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if onLeaf {
		der, err := x509.CreateCertificate(rand.Reader, leafTemplate, &x509.Certificate{Subject: issuer}, costly, signer)
		if err != nil {
			t.Fatalf("create leaf: %v", err)
		}
		return [][]byte{der}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, &x509.Certificate{Subject: issuer}, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: issuer,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}, costly, signer)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	return [][]byte{withJunkSignature(t, leafDER, bits), intermediateDER}
}

// withJunkSignature replaces der's signature with bits/8 random bytes,
// as long as an RSA signature by a key of that modulus would be.
func withJunkSignature(t *testing.T, der []byte, bits int) []byte {
	t.Helper()
	var cert struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		t.Fatalf("unmarshal certificate: %v", err)
	}
	sig := make([]byte, bits/8)
	_, _ = rand.Read(sig)
	sig[0] = 0x01
	cert.Sig = asn1.BitString{Bytes: sig, BitLength: bits}
	out, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}
	return out
}
