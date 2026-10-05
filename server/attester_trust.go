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
	"slices"
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
//   - RegisteredAttesterKeys looks the key up in an AttesterKeySource by
//     the client's registered attester and "kid", ignoring any "x5c".
//
// A deployment customises which anchors to trust — per client, from a
// trust list, refreshed however it likes — through X5CAttesterChain's
// TrustAnchors (an AttesterTrustAnchors) or, under
// AttesterIssuerBoundToAnchor, its Anchors (an AttesterAnchorSource,
// which also binds each anchor to the attesters it may vouch for),
// never by resolving keys itself, so certificate path validation always
// happens here rather than in code that could forget to do it.
type AttesterTrust interface {
	attesterKey(ctx context.Context, s *Server, client storage.RegisteredClient, attestation clientattestation.Attestation) (crypto.PublicKey, error)
	validate() error
}

// RegisteredAttesterKeys verifies a client's attestation with a key
// Keys returns for the client's registered attester
// (storage.RegisteredClient.ExpectedAttesterIssuer), selected by the
// attestation's "kid" (any key with the client's registered attestation
// algorithm when there is no "kid"). Any "x5c" header is ignored, not
// validated — so rotating an Attester's signing key means
// re-registering it, and a certificate's expiry or trust status plays
// no part. Use X5CAttesterChain for HAIP's certificate-based trust.
//
// Attester keys come from their own source, keyed by attester, never
// from Dependencies.ClientKeys: a key source that answers by client
// (keys/ephemeral's, or federation's, which returns a relying party's
// own published keys) would hand back a client's own key, and the
// client could attest for itself.
type RegisteredAttesterKeys struct {
	// Keys resolves each attester's verification keys, by its issuer —
	// keys.StaticAttesterKeys, or your own keys.AttesterKeySource.
	// Required; under AssuranceProduction it must declare
	// keys.KeySourceAssurance, as Dependencies.ClientKeys must.
	Keys keys.AttesterKeySource
}

func (r RegisteredAttesterKeys) attesterKey(ctx context.Context, _ *Server, client storage.RegisteredClient, attestation clientattestation.Attestation) (crypto.PublicKey, error) {
	alg, kid := client.ClientAttestationAlgorithm(), attestation.KeyID()
	set, err := r.Keys.ResolveAttesterKeys(ctx, keys.AttesterKeyRequest{
		Issuer: client.ExpectedAttesterIssuer(), Algorithm: alg, KeyID: kid,
	})
	if err != nil {
		return nil, err
	}
	return selectVerificationKey(set, alg, kid)
}

func (r RegisteredAttesterKeys) validate() error {
	if r.Keys == nil {
		return errors.New("server: dependencies: attester trust: RegisteredAttesterKeys needs Keys, the attesters' own key source (e.g. keys.StaticAttesterKeys)")
	}
	return nil
}

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
	// must verify against, under AttesterIssuerInCertificate and
	// AttesterIssuerByTrustAnchors. Required for those modes, and must be
	// nil under AttesterIssuerBoundToAnchor, which reads Anchors instead.
	// New refuses a value that is also an AttesterAnchorSource: anchors
	// bound to attesters belong in Anchors, under
	// AttesterIssuerBoundToAnchor, where the bindings are checked —
	// TrustAnchors would treat them as one unbound pool.
	TrustAnchors AttesterTrustAnchors

	// Anchors supplies the anchors, each bound to the attesters it may
	// vouch for, under AttesterIssuerBoundToAnchor. Required for that
	// mode, and must be nil under the others — New refuses a
	// configuration where it's unclear which field applies.
	Anchors AttesterAnchorSource

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
	// equal. That stops an attester from claiming another's identity
	// only while it can't put that identity in a certificate: with
	// anchors shared between attesters — a trust list, one anchor pool
	// for every client — any attester that runs a CA under any of the
	// anchors (or holds an intermediate without name constraints) can
	// issue itself a certificate naming another attester, and attest for
	// that attester's clients. Choose AttesterIssuerBoundToAnchor for
	// shared trust lists; this mode suits anchors that issue only to
	// attesters they have vetted for every identifier they certify.
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

	// AttesterIssuerBoundToAnchor requires what AttesterIssuerInCertificate
	// does — a URI subject alternative name exactly equal to the client's
	// ExpectedAttesterIssuer — and, in addition, that the chain verify to
	// an anchor bound to that identifier. Each anchor carries the
	// attester identifiers it may vouch for (AttesterAnchor), so a CA
	// under attester A's anchor can't issue a certificate that
	// authenticates attester B's clients, even in a pool shared by every
	// attester. Configure the anchors through X5CAttesterChain.Anchors
	// (StaticAttesterAnchors, or an AttesterAnchorSource of your own),
	// not TrustAnchors. Choose it for a trust list of several attesters'
	// own CAs.
	AttesterIssuerBoundToAnchor
)

func (c X5CAttesterChain) validate() error {
	switch c.IssuerBinding {
	case AttesterIssuerInCertificate, AttesterIssuerByTrustAnchors, AttesterIssuerBoundToAnchor:
	default:
		return fmt.Errorf("server: dependencies: attester_trust: X5CAttesterChain.IssuerBinding is required (AttesterIssuerInCertificate, AttesterIssuerByTrustAnchors or AttesterIssuerBoundToAnchor)")
	}
	if c.IssuerBinding == AttesterIssuerBoundToAnchor {
		return c.validateBoundAnchors()
	}
	if c.Anchors != nil {
		return fmt.Errorf("server: dependencies: attester_trust: X5CAttesterChain.Anchors applies only to AttesterIssuerBoundToAnchor; use TrustAnchors")
	}
	if c.TrustAnchors == nil {
		return fmt.Errorf("server: dependencies: attester_trust: X5CAttesterChain.TrustAnchors is required")
	}
	if static, ok := c.TrustAnchors.(StaticAttesterTrustAnchors); ok && static.Roots == nil {
		return fmt.Errorf("server: dependencies: attester_trust: StaticAttesterTrustAnchors.Roots is required")
	}
	if _, ok := c.TrustAnchors.(AttesterAnchorSource); ok {
		return fmt.Errorf("server: dependencies: attester_trust: X5CAttesterChain.TrustAnchors is an AttesterAnchorSource, whose attester bindings TrustAnchors would ignore; set it as Anchors with IssuerBinding AttesterIssuerBoundToAnchor")
	}
	return nil
}

// validateBoundAnchors checks an AttesterIssuerBoundToAnchor
// configuration: Anchors set, TrustAnchors not, and static anchors usable.
func (c X5CAttesterChain) validateBoundAnchors() error {
	if c.TrustAnchors != nil {
		return fmt.Errorf("server: dependencies: attester_trust: AttesterIssuerBoundToAnchor reads X5CAttesterChain.Anchors; leave TrustAnchors nil")
	}
	if c.Anchors == nil {
		return fmt.Errorf("server: dependencies: attester_trust: AttesterIssuerBoundToAnchor needs X5CAttesterChain.Anchors")
	}
	if static, ok := c.Anchors.(StaticAttesterAnchors); ok {
		if err := checkAttesterAnchors(static); err != nil {
			return fmt.Errorf("server: dependencies: attester_trust: StaticAttesterAnchors: %w", err)
		}
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
	roots, anchors, err := c.resolveAnchors(ctx, client)
	if err != nil {
		return nil, err
	}
	leaf, chains, err := verifyAttesterChain(ders, roots, s.deps.Clock.Now())
	if err != nil {
		return nil, err
	}
	if !keyFitsAlgorithm(leaf.PublicKey, client.ClientAttestationAlgorithm()) {
		return nil, fmt.Errorf("attester certificate key does not fit algorithm %s", client.ClientAttestationAlgorithm())
	}
	expected := client.ExpectedAttesterIssuer()
	if c.IssuerBinding != AttesterIssuerByTrustAnchors && !hasURIName(leaf, expected) {
		return nil, fmt.Errorf("attester certificate does not name the client's attester %q as a URI subject alternative name", expected)
	}
	if c.IssuerBinding == AttesterIssuerBoundToAnchor && !chainEndsAtAnchorFor(chains, anchors, expected) {
		return nil, fmt.Errorf("attester certificate chain does not end at a trust anchor bound to the client's attester %q", expected)
	}
	return leaf.PublicKey, nil
}

// resolveAnchors returns the pool a client's attestation chain must
// verify against and, under AttesterIssuerBoundToAnchor, the bound
// anchors it was built from.
func (c X5CAttesterChain) resolveAnchors(ctx context.Context, client storage.RegisteredClient) (*x509.CertPool, []AttesterAnchor, error) {
	if c.IssuerBinding == AttesterIssuerBoundToAnchor {
		anchors, err := c.Anchors.AttesterAnchors(ctx, client)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve attester trust anchors: %w", err)
		}
		if err := checkAttesterAnchors(anchors); err != nil {
			return nil, nil, fmt.Errorf("resolve attester trust anchors: %w", err)
		}
		pool := x509.NewCertPool()
		for _, a := range anchors {
			pool.AddCert(a.Certificate)
		}
		return pool, anchors, nil
	}
	roots, err := c.TrustAnchors.TrustAnchors(ctx, client)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve attester trust anchors: %w", err)
	}
	if roots == nil {
		return nil, nil, errors.New("no attester trust anchors for this client")
	}
	return roots, nil, nil
}

// chainEndsAtAnchorFor reports whether one of chains — each leaf first,
// anchor last, as x509.Certificate.Verify returns them — ends at an
// anchor bound to issuer.
func chainEndsAtAnchorFor(chains [][]*x509.Certificate, anchors []AttesterAnchor, issuer string) bool {
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		for _, a := range anchors {
			if a.Certificate.Equal(root) && slices.Contains(a.Issuers, issuer) {
				return true
			}
		}
	}
	return false
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

// AttesterAnchor is a trust anchor bound to the attester identifiers it
// may vouch for, for AttesterIssuerBoundToAnchor: an attestation chain
// ending at Certificate authenticates a client only if the client's
// ExpectedAttesterIssuer is one of Issuers (and the signing certificate
// names it).
type AttesterAnchor struct {
	// Certificate is the anchor. Required.
	Certificate *x509.Certificate

	// Issuers are the attester identifiers — what clients register as
	// ExpectedAttesterIssuer — this anchor may vouch for. At least one.
	Issuers []string
}

// AttesterAnchorSource supplies, for AttesterIssuerBoundToAnchor, the
// anchors a client's attestation chain must verify against, each bound
// to the attester identifiers it may vouch for. Like
// AttesterTrustAnchors, it is consulted on every attestation, so a
// trust-list-backed implementation can refresh or withdraw anchors.
// Returning no anchors rejects the attestation.
type AttesterAnchorSource interface {
	AttesterAnchors(ctx context.Context, client storage.RegisteredClient) ([]AttesterAnchor, error)
}

// StaticAttesterAnchors trusts the same bound anchors for every client,
// for X5CAttesterChain.Anchors under AttesterIssuerBoundToAnchor: a
// trust list of several attesters' own CAs, each bound to the attesters
// it certifies. It is deliberately not an AttesterTrustAnchors, so it
// can't be set as TrustAnchors, where its bindings would be ignored.
// New refuses an empty list, an anchor without a certificate, and an
// anchor bound to no attester.
type StaticAttesterAnchors []AttesterAnchor

// AttesterAnchors implements AttesterAnchorSource.
func (a StaticAttesterAnchors) AttesterAnchors(context.Context, storage.RegisteredClient) ([]AttesterAnchor, error) {
	return a, nil
}

// checkAttesterAnchors refuses an empty anchor list, an anchor without a
// certificate, and an anchor bound to no attester.
func checkAttesterAnchors(anchors []AttesterAnchor) error {
	if len(anchors) == 0 {
		return errors.New("no attester trust anchors")
	}
	for i, a := range anchors {
		if a.Certificate == nil {
			return fmt.Errorf("anchor %d has no certificate", i)
		}
		if len(a.Issuers) == 0 {
			return fmt.Errorf("anchor %d (%s) is bound to no attester", i, a.Certificate.Subject)
		}
		for _, issuer := range a.Issuers {
			if issuer == "" {
				return fmt.Errorf("anchor %d (%s) has an empty attester identifier", i, a.Certificate.Subject)
			}
		}
	}
	return nil
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
// against roots at now, returning it and the chains that verify (each
// ending at an anchor); see X5CAttesterChain for the rules.
func verifyAttesterChain(ders [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, [][]*x509.Certificate, error) {
	if len(ders) == 0 {
		return nil, nil, errors.New("attester certificate chain is empty")
	}
	certs := make([]*x509.Certificate, len(ders))
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("parse x5c certificate %d: %w", i, err)
		}
		certs[i] = cert
	}
	leaf := certs[0]
	if isSelfSigned(leaf) {
		return nil, nil, errors.New("attester certificate must not be self-signed")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, errors.New("attester certificate key usage does not permit digital signatures")
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attester certificate chain does not verify: %w", err)
	}
	return leaf, chains, nil
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
