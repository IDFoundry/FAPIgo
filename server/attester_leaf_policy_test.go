package server_test

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

var (
	oidMDLDocumentSigner = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}
	oidMdocReaderAuth    = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
	oidWalletProvider    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1} // a private purpose
)

// attesterLeaf is an attester signing certificate and the x5c that
// carries it.
type attesterLeaf struct {
	leaf testCert
	x5c  json.RawMessage
}

// roleLeaves issues, under root, the attester certificates the default
// leaf policy refuses (other roles' certificates) and accepts.
func roleLeaves(t *testing.T, root testCert) (refused, accepted map[string]attesterLeaf) {
	t.Helper()
	leaf := func(name string, o certOptions) attesterLeaf {
		o.parent = &root
		l := newTestCert(t, name, o)
		return attesterLeaf{l, x5cOf(l)}
	}
	tlsCA := newTestCert(t, "TLS-only CA", certOptions{parent: &root, isCA: true, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	underTLSCA := newTestCert(t, "attester under TLS CA", certOptions{parent: &tlsCA})
	refused = map[string]attesterLeaf{
		"TLS server":                      leaf("tls server", certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}),
		"TLS client and private purpose":  leaf("tls client", certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, unknownExtKeyUsage: []asn1.ObjectIdentifier{oidWalletProvider}}),
		"OCSP responder":                  leaf("ocsp", certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}),
		"mdoc reader":                     leaf("mdoc reader", certOptions{unknownExtKeyUsage: []asn1.ObjectIdentifier{oidMdocReaderAuth}}),
		"mDL document signer":             leaf("mdl ds", certOptions{unknownExtKeyUsage: []asn1.ObjectIdentifier{oidMDLDocumentSigner}}),
		"only path through a TLS-only CA": {underTLSCA, x5cOf(underTLSCA, tlsCA)},
	}
	accepted = map[string]attesterLeaf{
		"no extended key usage": leaf("plain", certOptions{}),
		"private purpose only":  leaf("private", certOptions{unknownExtKeyUsage: []asn1.ObjectIdentifier{oidWalletProvider}}),
		"anyExtendedKeyUsage":   leaf("any", certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}),
	}
	return refused, accepted
}

// leafPolicyHarness is a harness trusting root for every client, with
// policy as the X5CAttesterChain's LeafPolicy.
func leafPolicyHarness(t *testing.T, root testCert, policy server.AttesterLeafPolicy) harness {
	t.Helper()
	return newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
		Revocation:    server.NoClientCertificateRevocationCheck{},
		TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
		IssuerBinding: server.AttesterIssuerByTrustAnchors,
		LeafPolicy:    policy,
	})
}

// checkAttesterLeaf runs a client_credentials request with an
// attestation signed by l, and checks it succeeds or fails with
// invalid_client.
func checkAttesterLeaf(t *testing.T, h harness, l attesterLeaf, wantOK bool) {
	t.Helper()
	instanceKey := generateKey(t)
	err := requestWithAttestation(t, h, createX5CAttestation(t, l.leaf.key, l.x5c, "", &instanceKey.PublicKey, h.now), instanceKey)
	if wantOK {
		if err != nil {
			t.Fatalf("RequestClientCredentialsToken: %v", err)
		}
		return
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q (%v), want %q", code, err, server.ErrorInvalidClient)
	}
}

// TestX5CAttesterChainDefaultLeafPolicy covers the default role policy:
// with LeafPolicy nil, a certificate issued for another role (TLS, OCSP,
// an ISO/IEC 18013-5 role, or under a TLS-only CA) can't sign an
// attestation, while a certificate naming no other role can.
func TestX5CAttesterChainDefaultLeafPolicy(t *testing.T) {
	root := newTestCert(t, "ecosystem CA", certOptions{isCA: true})
	refused, accepted := roleLeaves(t, root)
	for name, l := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			checkAttesterLeaf(t, leafPolicyHarness(t, root, nil), l, false)
		})
	}
	for name, l := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			checkAttesterLeaf(t, leafPolicyHarness(t, root, nil), l, true)
		})
	}
}

// TestX5CAttesterChainDefaultLeafPolicyNamedIssuer covers a TLS
// certificate for the Wallet Provider's own origin, which carries the
// URI subject alternative name AttesterIssuerInCertificate looks for,
// at the token endpoint and AuthenticateAttestedClient.
func TestX5CAttesterChainDefaultLeafPolicyNamedIssuer(t *testing.T) {
	root := newTestCert(t, "ecosystem CA", certOptions{isCA: true})
	tlsCert := newTestCert(t, "attester web origin", certOptions{parent: &root, uris: []string{testAttesterIssuer}, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	h := newHarnessWithAttesterTrust(t, nil, server.X5CAttesterChain{
		Revocation:    server.NoClientCertificateRevocationCheck{},
		TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: poolOf(root)},
		IssuerBinding: server.AttesterIssuerInCertificate,
	})
	checkAttesterLeaf(t, h, attesterLeaf{tlsCert, x5cOf(tlsCert)}, false)

	instanceKey := generateKey(t)
	_, err := h.server.AuthenticateAttestedClient(context.Background(), server.AttestedClientAuthenticationRequest{
		ClientAttestations:    []string{createX5CAttestation(t, tlsCert.key, x5cOf(tlsCert), "", &instanceKey.PublicKey, h.now)},
		ClientAttestationPoPs: []string{createAttestationPoPHeader(t, instanceKey, testClientID.String(), testIssuer, "jti-tls", h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("AuthenticateAttestedClient error code = %q (%v), want %q", code, err, server.ErrorInvalidClient)
	}
}

// TestAnyAttesterLeafAcceptsOtherRoles covers the explicit opt-out:
// every certificate the default refuses signs attestations again.
func TestAnyAttesterLeafAcceptsOtherRoles(t *testing.T) {
	root := newTestCert(t, "ecosystem CA", certOptions{isCA: true})
	refused, _ := roleLeaves(t, root)
	for name, l := range refused {
		t.Run(name, func(t *testing.T) {
			checkAttesterLeaf(t, leafPolicyHarness(t, root, server.AnyAttesterLeaf{}), l, true)
		})
	}
}

// TestAttesterLeafPolicyFuncAddsRequirement covers an ecosystem policy
// that requires its own Wallet Provider purpose on top of the default.
func TestAttesterLeafPolicyFuncAddsRequirement(t *testing.T) {
	root := newTestCert(t, "ecosystem CA", certOptions{isCA: true})
	refused, accepted := roleLeaves(t, root)
	policy := server.AttesterLeafPolicyFunc(func(chain []*x509.Certificate) error {
		if err := (server.DefaultAttesterLeafPolicy{}).CheckAttesterChain(chain); err != nil {
			return err
		}
		if !slices.ContainsFunc(chain[0].UnknownExtKeyUsage, oidWalletProvider.Equal) {
			return errors.New("not a Wallet Provider certificate")
		}
		return nil
	})
	for name, l := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			checkAttesterLeaf(t, leafPolicyHarness(t, root, policy), l, false)
		})
	}
	for name, l := range accepted {
		t.Run(name, func(t *testing.T) {
			checkAttesterLeaf(t, leafPolicyHarness(t, root, policy), l, name == "private purpose only")
		})
	}
}

// TestAttesterLeafPolicyBeforeAnchorBinding covers a signing certificate
// with two verified paths under AttesterIssuerBoundToAnchor: through a
// TLS-only cross-certificate of its issuing CA to an anchor bound to the
// client's attester, and through an unrestricted one to an anchor bound
// to another attester. Only a chain the leaf policy approves may
// satisfy the binding, so the default refuses it.
func TestAttesterLeafPolicyBeforeAnchorBinding(t *testing.T) {
	boundRoot := newTestCert(t, "attester B CA", certOptions{isCA: true})
	otherRoot := newTestCert(t, "attester A CA", certOptions{isCA: true})
	issuingKey := generateKey(t)
	viaTLS := newTestCert(t, "issuing CA", certOptions{parent: &boundRoot, isCA: true, key: issuingKey, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	viaOther := newTestCert(t, "issuing CA", certOptions{parent: &otherRoot, isCA: true, key: issuingKey})
	leaf := newTestCert(t, "B", certOptions{parent: &viaOther, uris: []string{testAttesterIssuer}})
	anchors := server.StaticAttesterAnchors{
		{Certificate: boundRoot.cert, Issuers: []string{testAttesterIssuer}},
		{Certificate: otherRoot.cert, Issuers: []string{otherAttesterIssuer}},
	}
	l := attesterLeaf{leaf, x5cOf(leaf, viaTLS, viaOther)}
	for name, tc := range map[string]struct {
		policy server.AttesterLeafPolicy
		wantOK bool
	}{
		"default refuses":          {nil, false},
		"AnyAttesterLeaf opts out": {server.AnyAttesterLeaf{}, true},
	} {
		t.Run(name, func(t *testing.T) {
			trust := boundChain(anchors)
			trust.LeafPolicy = tc.policy
			checkAttesterLeaf(t, newHarnessWithAttesterTrust(t, nil, trust), l, tc.wantOK)
		})
	}
}

// TestDefaultAttesterLeafPolicyRoles covers DefaultAttesterLeafPolicy's
// role rules directly, chain by chain.
func TestDefaultAttesterLeafPolicyRoles(t *testing.T) {
	root := newTestCert(t, "root", certOptions{isCA: true})
	ca := func(o certOptions) testCert {
		o.parent, o.isCA = &root, true
		return newTestCert(t, "CA", o)
	}
	leafUnder := func(issuer testCert, o certOptions) []*x509.Certificate {
		o.parent = &issuer
		return []*x509.Certificate{newTestCert(t, "leaf", o).cert, issuer.cert, root.cert}
	}
	plainCA := ca(certOptions{})
	for name, tc := range map[string]struct {
		chain  []*x509.Certificate
		wantOK bool
	}{
		"empty chain":                       {nil, false},
		"code signing leaf":                 {leafUnder(plainCA, certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}), false},
		"email protection leaf":             {leafUnder(plainCA, certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}), false},
		"time stamping leaf":                {leafUnder(plainCA, certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}), false},
		"IPsec user leaf":                   {leafUnder(plainCA, certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECUser}}), false},
		"anyExtendedKeyUsage and TLS leaf":  {leafUnder(plainCA, certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth}}), false},
		"private purpose and mdoc reader":   {leafUnder(plainCA, certOptions{unknownExtKeyUsage: []asn1.ObjectIdentifier{oidWalletProvider, oidMdocReaderAuth}}), false},
		"CA restricted to mDL signing":      {leafUnder(ca(certOptions{unknownExtKeyUsage: []asn1.ObjectIdentifier{oidMDLDocumentSigner}}), certOptions{}), false},
		"CA restricted to TLS and OCSP":     {leafUnder(ca(certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning}}), certOptions{}), false},
		"anchor restricted to TLS":          {[]*x509.Certificate{newTestCert(t, "leaf", certOptions{parent: &root}).cert, ca(certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}).cert}, false},
		"CA with TLS and a private purpose": {leafUnder(ca(certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, unknownExtKeyUsage: []asn1.ObjectIdentifier{oidWalletProvider}}), certOptions{}), true},
		"CA with anyExtendedKeyUsage":       {leafUnder(ca(certOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth}}), certOptions{}), true},
		"unrestricted CA":                   {leafUnder(plainCA, certOptions{}), true},
	} {
		t.Run(name, func(t *testing.T) {
			err := (server.DefaultAttesterLeafPolicy{}).CheckAttesterChain(tc.chain)
			if (err == nil) != tc.wantOK {
				t.Fatalf("CheckAttesterChain = %v, want ok %v", err, tc.wantOK)
			}
		})
	}
}
