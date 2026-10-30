package server

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// AttesterLeafPolicy decides whether a verified X5CAttesterChain
// certificate chain may sign Wallet Attestations, by the role its
// certificates were issued for — X5CAttesterChain.LeafPolicy. Path
// validation proves only that an anchor certified the signing
// certificate, not for what: an anchor that also certifies TLS servers,
// OCSP responders or mdoc readers would otherwise turn each of those
// keys, often online and less protected than a Wallet Provider's
// attestation key, into an attestation key.
//
// CheckAttesterChain is given one verified chain, leaf first and ending
// at the trust anchor, as x509.Certificate.Verify returns it, and
// returns an error to refuse it. It runs on every chain that verified;
// the attestation is refused, with invalid_client, when it refuses them
// all, and only the chains it accepts go on to the issuer binding
// (AttesterIssuerBoundToAnchor) and Revocation checks.
//
// DefaultAttesterLeafPolicy is what a nil LeafPolicy applies.
// AttesterLeafPolicyFunc adapts a function, so an ecosystem that defines
// its own Wallet Provider extended key usage or certificate policy can
// require it on top of DefaultAttesterLeafPolicy; AnyAttesterLeaf
// explicitly declines any role check.
type AttesterLeafPolicy interface {
	CheckAttesterChain(chain []*x509.Certificate) error
}

// AttesterLeafPolicyFunc adapts a function to an AttesterLeafPolicy. A
// policy that adds a requirement calls DefaultAttesterLeafPolicy first,
// so it only narrows the default:
//
//	server.AttesterLeafPolicyFunc(func(chain []*x509.Certificate) error {
//		if err := (server.DefaultAttesterLeafPolicy{}).CheckAttesterChain(chain); err != nil {
//			return err
//		}
//		if !slices.ContainsFunc(chain[0].UnknownExtKeyUsage, walletProviderEKU.Equal) {
//			return errors.New("not a Wallet Provider certificate")
//		}
//		return nil
//	})
type AttesterLeafPolicyFunc func(chain []*x509.Certificate) error

// CheckAttesterChain implements AttesterLeafPolicy by calling f.
func (f AttesterLeafPolicyFunc) CheckAttesterChain(chain []*x509.Certificate) error {
	return f(chain)
}

// DefaultAttesterLeafPolicy refuses a chain whose certificates say they
// belong to a role other than attestation signing. No standard extended
// key usage exists for attestation signing, so it can't require one;
// it refuses the roles it can recognise instead:
//
//   - a signing certificate whose extended key usage lists any purpose
//     crypto/x509 names other than anyExtendedKeyUsage — TLS server or
//     client authentication, code signing, email protection, time
//     stamping, OCSP signing (id-kp-OCSPSigning), IPsec, or the vendor
//     server-gated-crypto and code-signing purposes — even alongside
//     other purposes, since the certificate then also serves that role
//     and its key may be held where that role is;
//   - a signing certificate whose extended key usage lists an
//     ISO/IEC 18013-5 role: mDL document signer (1.0.18013.5.1.2) or
//     mdoc reader authentication (1.0.18013.5.1.6);
//   - a chain through a CA certificate (an intermediate or the anchor)
//     whose extended key usage lists only such purposes, such as a CA
//     restricted to issuing TLS certificates, so a certificate under it
//     is that role's even when it lists no extended key usage itself. A
//     CA certificate whose list includes anyExtendedKeyUsage or a purpose
//     not named above doesn't restrict the chain to those roles.
//
// It accepts a signing certificate with no extended key usage, with
// anyExtendedKeyUsage, or with purposes of its own (an ecosystem's
// Wallet Provider purpose, say) only.
type DefaultAttesterLeafPolicy struct{}

// CheckAttesterChain implements AttesterLeafPolicy.
func (DefaultAttesterLeafPolicy) CheckAttesterChain(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("empty attester certificate chain")
	}
	leaf := chain[0]
	for _, eku := range leaf.ExtKeyUsage {
		if eku != x509.ExtKeyUsageAny {
			return fmt.Errorf("attester certificate's extended key usage lists another role (%s)", extKeyUsageName(eku))
		}
	}
	for _, oid := range leaf.UnknownExtKeyUsage {
		if isISO18013Role(oid) {
			return fmt.Errorf("attester certificate's extended key usage lists an ISO/IEC 18013-5 role (%s)", oid)
		}
	}
	for _, ca := range chain[1:] {
		if restrictedToOtherRoles(ca) {
			return fmt.Errorf("attester certificate chains through %q, a CA restricted to other roles' certificates", ca.Subject)
		}
	}
	return nil
}

// AnyAttesterLeaf explicitly declines a role check on X5CAttesterChain
// signing certificates: any certificate that chains to an anchor may
// sign attestations, whatever extended key usage it or its issuers
// list. Right only when the anchors certify nothing but attesters.
// Exists so declining is a conscious, visible line of code, the same
// reason NoClientCertificateRevocationCheck exists.
type AnyAttesterLeaf struct{}

// CheckAttesterChain implements AttesterLeafPolicy by accepting every
// chain.
func (AnyAttesterLeaf) CheckAttesterChain([]*x509.Certificate) error {
	return nil
}

// ISO/IEC 18013-5 Annex B extended key usages, which crypto/x509 leaves
// in UnknownExtKeyUsage.
var (
	oidMDLDocumentSigner = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}
	oidMdocReaderAuth    = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
)

func isISO18013Role(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidMDLDocumentSigner) || oid.Equal(oidMdocReaderAuth)
}

// restrictedToOtherRoles reports whether ca's extended key usage is
// present and lists only purposes DefaultAttesterLeafPolicy refuses in
// a signing certificate.
func restrictedToOtherRoles(ca *x509.Certificate) bool {
	if len(ca.ExtKeyUsage) == 0 && len(ca.UnknownExtKeyUsage) == 0 {
		return false
	}
	return !slices.Contains(ca.ExtKeyUsage, x509.ExtKeyUsageAny) &&
		!slices.ContainsFunc(ca.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool { return !isISO18013Role(oid) })
}

// extKeyUsageName names eku for an error message.
func extKeyUsageName(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageServerAuth:
		return "TLS server authentication"
	case x509.ExtKeyUsageClientAuth:
		return "TLS client authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "code signing"
	case x509.ExtKeyUsageEmailProtection:
		return "email protection"
	case x509.ExtKeyUsageTimeStamping:
		return "time stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP signing"
	default:
		return fmt.Sprintf("crypto/x509 extended key usage %d", eku)
	}
}

// approvedAttesterChains returns those of chains policy accepts, in
// order, or, when it accepts none, the error it gave the first.
func approvedAttesterChains(policy AttesterLeafPolicy, chains [][]*x509.Certificate) ([][]*x509.Certificate, error) {
	if policy == nil {
		policy = DefaultAttesterLeafPolicy{}
	}
	var approved [][]*x509.Certificate
	var firstErr error
	for _, chain := range chains {
		if err := policy.CheckAttesterChain(chain); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		approved = append(approved, chain)
	}
	if len(approved) == 0 {
		// Verify returns at least one chain on success, so firstErr is
		// set; were chains empty, this still fails closed.
		return nil, fmt.Errorf("attester certificate is not accepted for attestation signing: %w", firstErr)
	}
	return approved, nil
}
