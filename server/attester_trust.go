package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AttesterTrust decides how this server establishes the key that
// verifies a client's attestation (OAuth 2.0 Attestation-Based Client
// Authentication — a Wallet Attestation, under HAIP) — Dependencies.
// AttesterTrust, required when Config.AttestationBasedClientAuthentication
// is set. There is deliberately no default: whether attestations are
// trusted by pre-registered keys or by a certificate chain to a trust
// anchor is a choice every deployment makes explicitly, the same stance
// ClientCertificateTrust takes for mTLS.
//
// It can only be one of this package's own implementations:
//
//   - X5CAttesterChain verifies the attestation's "x5c" certificate
//     chain against trust anchors — what HAIP 1.0 §4.4.1 expects;
//   - RegisteredAttesterKeys looks the key up in Dependencies.ClientKeys
//     by "kid", ignoring any "x5c".
//
// A deployment customises which anchors to trust — per client, from a
// trust list, refreshed however it likes — through X5CAttesterChain's
// AttesterTrustAnchors, never by resolving keys itself, so certificate
// path validation always happens here rather than in code that could
// forget to do it.
type AttesterTrust interface {
	attesterKey(ctx context.Context, s *Server, client storage.RegisteredClient, attestation clientattestation.Attestation) (crypto.PublicKey, error)
	validate() error
}

// RegisteredAttesterKeys verifies a client's attestation with a key
// Dependencies.ClientKeys returns for keys.AttestationVerification,
// selected by the attestation's "kid" (any key with the client's
// registered attestation algorithm when there is no "kid"). Any "x5c"
// header is ignored, not validated — so rotating an Attester's signing
// key means re-registering it, and a certificate's expiry or trust
// status plays no part. Use X5CAttesterChain for HAIP's certificate-
// based trust.
type RegisteredAttesterKeys struct{}

func (RegisteredAttesterKeys) attesterKey(ctx context.Context, s *Server, client storage.RegisteredClient, attestation clientattestation.Attestation) (crypto.PublicKey, error) {
	return s.resolveClientKey(ctx, client.ID(), keys.AttestationVerification, client.ClientAttestationAlgorithm(), attestation.KeyID())
}

func (RegisteredAttesterKeys) validate() error { return nil }

// X5CAttesterChain verifies a client's attestation with the key of the
// certificate in its "x5c" header (HAIP 1.0 §4.4.1), after verifying
// that certificate's chain against the anchors TrustAnchors returns for
// the client. An attestation without "x5c" is rejected — there is no
// fallback to "kid", which would let an attestation skip the chain
// check just by omitting it — and "kid" plays no part.
//
// The signing certificate must:
//
//   - chain to one of the anchors through the other "x5c" certificates,
//     valid at the server's Clock time (not the wall clock);
//   - not be self-signed, even if it is itself an anchor — HAIP keeps
//     the trust anchor out of "x5c" and rejects self-signed signing
//     certificates wherever else it uses x5c, so the signing key can be
//     rotated or revoked without redistributing anchors;
//   - permit digital signatures, if it restricts key usage at all;
//   - hold a key of the type the client's registered attestation
//     algorithm needs.
//
// Extended key usage isn't constrained: no standard value exists for
// attestation signing. Revocation isn't checked — an
// AttesterTrustAnchors that tracks a trust list can stop returning an
// anchor that has been withdrawn.
//
// A valid chain proves only that some attester certified under an
// anchor signed the attestation, not which one. The attestation's "iss"
// is checked against the client's ExpectedAttesterIssuer, but "iss" is
// a claim the attester writes itself, so on its own it binds nothing:
// with anchors shared between attesters — a trust list whose CA
// certifies many Wallet Providers, StaticAttesterTrustAnchors across
// clients, let alone public web PKI roots — any of them could attest
// for any client. IssuerBinding says what ties the certificate to the
// client's attester instead; see AttesterIssuerBinding.
type X5CAttesterChain struct {
	// TrustAnchors supplies the anchors a client's attestation chain
	// must verify against. Required.
	TrustAnchors AttesterTrustAnchors

	// IssuerBinding decides what ties the signing certificate to the
	// client's registered attester. Required, with no default — see
	// AttesterIssuerBinding.
	IssuerBinding AttesterIssuerBinding
}

// AttesterIssuerBinding decides what ties an X5CAttesterChain signing
// certificate to the client's registered attester
// (storage.RegisteredClient.ExpectedAttesterIssuer). There is no default:
// the choice depends on how a deployment's anchors are shared, which
// this package can't see.
type AttesterIssuerBinding uint8

const (
	_ AttesterIssuerBinding = iota

	// AttesterIssuerInCertificate requires the signing certificate to
	// carry a URI subject alternative name exactly equal to the client's
	// ExpectedAttesterIssuer, which the attestation's "iss" must also
	// equal. The certificate then names the attester, so anchors may be
	// shared between attesters — a trust list, one anchor pool for every
	// client — without one attester being able to attest for another's
	// clients. Choose it whenever the attesters' certificates carry their
	// identifier this way.
	AttesterIssuerInCertificate

	// AttesterIssuerByTrustAnchors ties nothing in the certificate to the
	// attester: it declares that the anchors TrustAnchors returns for a
	// client are specific to that client's attester — every certificate
	// chaining to them belongs to the attester the client is registered
	// with — so the anchors themselves are the binding. That is the
	// deployment's guarantee, not something this package checks: shared
	// anchors (a multi-provider trust-list CA, StaticAttesterTrustAnchors
	// serving clients of different attesters, system or web PKI roots)
	// break it, and with it client authentication. Choose it only for
	// attester certificates that carry no usable identifier.
	AttesterIssuerByTrustAnchors
)

func (c X5CAttesterChain) validate() error {
	if c.IssuerBinding != AttesterIssuerInCertificate && c.IssuerBinding != AttesterIssuerByTrustAnchors {
		return fmt.Errorf("server: dependencies: attester_trust: X5CAttesterChain.IssuerBinding is required (AttesterIssuerInCertificate or AttesterIssuerByTrustAnchors)")
	}
	if c.TrustAnchors == nil {
		return fmt.Errorf("server: dependencies: attester_trust: X5CAttesterChain.TrustAnchors is required")
	}
	if static, ok := c.TrustAnchors.(StaticAttesterTrustAnchors); ok && static.Roots == nil {
		return fmt.Errorf("server: dependencies: attester_trust: StaticAttesterTrustAnchors.Roots is required")
	}
	return nil
}

func (c X5CAttesterChain) attesterKey(ctx context.Context, s *Server, client storage.RegisteredClient, attestation clientattestation.Attestation) (crypto.PublicKey, error) {
	ders, present, err := attestation.CertificateChain()
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, errors.New("attestation has no x5c certificate chain")
	}
	roots, err := c.TrustAnchors.TrustAnchors(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("resolve attester trust anchors: %w", err)
	}
	if roots == nil {
		return nil, errors.New("no attester trust anchors for this client")
	}
	leaf, err := verifyAttesterChain(ders, roots, s.deps.Clock.Now())
	if err != nil {
		return nil, err
	}
	if !keyFitsAlgorithm(leaf.PublicKey, client.ClientAttestationAlgorithm()) {
		return nil, fmt.Errorf("attester certificate key does not fit algorithm %s", client.ClientAttestationAlgorithm())
	}
	if c.IssuerBinding == AttesterIssuerInCertificate && !hasURIName(leaf, client.ExpectedAttesterIssuer()) {
		return nil, fmt.Errorf("attester certificate does not name the client's attester %q as a URI subject alternative name", client.ExpectedAttesterIssuer())
	}
	return leaf.PublicKey, nil
}

// hasURIName reports whether cert carries uri, exactly, as a URI
// subject alternative name — exact string comparison, the same way the
// attestation's "iss" is compared.
func hasURIName(cert *x509.Certificate, uri string) bool {
	for _, u := range cert.URIs {
		if u.String() == uri {
			return true
		}
	}
	return false
}

// AttesterTrustAnchors supplies the trust anchors X5CAttesterChain
// verifies a client's attestation certificate chain against. It is
// consulted on every attestation, so an implementation backed by a
// trust list can refresh or withdraw anchors without restarting the
// server, and can scope anchors per client (e.g. the Wallet Providers
// accepted for that client's wallet type). Returning a nil pool
// rejects the attestation.
type AttesterTrustAnchors interface {
	TrustAnchors(ctx context.Context, client storage.RegisteredClient) (*x509.CertPool, error)
}

// StaticAttesterTrustAnchors trusts the same anchors, Roots, for every
// client. With clients of more than one attester that pool is shared,
// so pair it with AttesterIssuerInCertificate — or keep it to a single
// attester's own anchors.
type StaticAttesterTrustAnchors struct {
	Roots *x509.CertPool
}

// TrustAnchors implements AttesterTrustAnchors.
func (a StaticAttesterTrustAnchors) TrustAnchors(context.Context, storage.RegisteredClient) (*x509.CertPool, error) {
	return a.Roots, nil
}

// verifyAttesterChain parses ders (leaf first) and verifies the leaf
// against roots at now; see X5CAttesterChain for the rules.
func verifyAttesterChain(ders [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(ders) == 0 {
		return nil, errors.New("attester certificate chain is empty")
	}
	certs := make([]*x509.Certificate, len(ders))
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse x5c certificate %d: %w", i, err)
		}
		certs[i] = cert
	}
	leaf := certs[0]
	if isSelfSigned(leaf) {
		return nil, errors.New("attester certificate must not be self-signed")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("attester certificate key usage does not permit digital signatures")
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("attester certificate chain does not verify: %w", err)
	}
	return leaf, nil
}

// isSelfSigned reports whether cert is signed by its own key —
// deliberately not CheckSignatureFrom, which also demands CA basic
// constraints a self-signed leaf typically lacks.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// keyFitsAlgorithm reports whether pub is the kind of key alg signs
// with, so a certificate for the wrong key type fails with a clear
// error before signature verification.
func keyFitsAlgorithm(pub crypto.PublicKey, alg fapi.SignatureAlgorithm) bool {
	switch alg {
	case fapi.ES256:
		k, ok := pub.(*ecdsa.PublicKey)
		return ok && k.Curve == elliptic.P256()
	case fapi.PS256:
		_, ok := pub.(*rsa.PublicKey)
		return ok
	case fapi.EdDSA:
		_, ok := pub.(ed25519.PublicKey)
		return ok
	default:
		return false
	}
}
