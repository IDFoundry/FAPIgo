package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/storage"
)

// ClientAttestationStatusChecker decides whether a verified Client
// Attestation is still valid — Dependencies.ClientAttestationStatus. An
// attestation's signature, lifetime and PoP prove only that its attester
// issued it to this Client Instance and hasn't let it expire; an
// attester that has since withdrawn it, for a wallet instance that has
// been compromised or deregistered, says so through a status mechanism
// such as a Token Status List (draft-ietf-oauth-status-list), which
// OpenID4VCI 1.0 Appendix E gives a Wallet Attestation as its optional
// "status" claim. OpenID4VCI §15.4.4 has every instance of a wallet
// share the attestation's sub, so a status list is the only way an
// attester can revoke a single instance: the client registration can't
// tell instances apart.
//
// This package doesn't fetch or interpret status lists itself: which
// status mechanism an attester uses, how its lists are signed and who
// may sign them, and how long a fetched list may be relied on are
// ecosystem decisions. The checker makes them, from what
// VerifiedClientAttestation carries. New can't see how a checker is
// configured to make them, so a checker checks that itself, through
// ClientAttestationStatusAssurance; AssuranceProduction requires that of
// every checker but NoClientAttestationStatusCheck.
type ClientAttestationStatusChecker interface {
	// CheckClientAttestationStatus returns nil when a's attestation is
	// still valid, an error wrapping ErrClientAttestationRevoked when it
	// isn't — the request is refused with invalid_client (401) — and any
	// other error when it couldn't decide (a status list it couldn't
	// fetch or verify, say), which refuses the request with server_error
	// (500): this package fails closed, without telling the client its
	// attestation is revoked when nobody knows. A checker that would
	// rather accept an attestation whose status it can't currently
	// determine (soft-fail) returns nil itself.
	//
	// It is called on every attestation-authenticated request — PAR, the
	// token endpoint (refresh included), CIBA, client_credentials,
	// revocation and AuthenticateAttestedClient — once the attestation
	// and its PoP have both verified and the PoP's jti has been recorded.
	// So only a caller holding the Client Instance Key can make this
	// server consult a status list (a replayed attestation is refused
	// before), and a request refused because the checker couldn't decide
	// is retried with a fresh PoP, which a client sends with every
	// request anyway. Caching is the checker's own: honour a Status List
	// Token's ttl and exp rather than fetching on every request.
	//
	// A checker that fetches a status list from a URI in the attestation
	// must fetch through fapihttp's hardened fetcher (fapihttp.New over
	// fapihttp.NewClient's client): the URI is the attester's to choose,
	// and the request reaches this method before anything about it is
	// trusted beyond the attestation's signature. It must also bind the
	// Status List Token's signer to the attester that signed the
	// attestation — through SignerKey or SignerCertificates — not merely
	// to a trust list: with anchors shared between attesters, another
	// Wallet Provider could otherwise sign a status list that decides
	// this one's attestations. Its CheckConfiguration
	// (ClientAttestationStatusAssurance) is where it refuses, when New
	// builds the server, a configuration that falls short of this: a
	// fetcher that isn't hardened, say.
	CheckClientAttestationStatus(ctx context.Context, a VerifiedClientAttestation) error
}

// ClientAttestationStatusAssurance is implemented by a
// ClientAttestationStatusChecker to check its own configuration, which
// New can't see: the fetcher a checker reaches the status-list URIs
// attestations name with, whether it checks a list signer's certificate
// for revocation, whether it caches the lists it fetches. When
// Config.AttestationBasedClientAuthentication is set, New calls
// CheckConfiguration with Config.Assurance, at every assurance level, so
// a checker applies its development rules as well as its production
// ones, and refuses to build the server on its error. Under
// AssuranceProduction New refuses a checker that doesn't implement it:
// the status-list fetch is otherwise the one outbound request whose
// hardening production never checks. NoClientAttestationStatusCheck,
// which fetches nothing, is accepted without it.
//
// A check describes the checking type's own configuration. A checker
// embedding one that implements it inherits the check through Go's
// method promotion, and New can't tell it from one the wrapper made
// itself: a wrapper embedding a status-list checker whose
// CheckClientAttestationStatus fetches some other way must override
// CheckConfiguration with a check of what its own fetching relies on. A
// struct embedding NoClientAttestationStatusCheck inherits no check, so
// under AssuranceProduction it must implement this itself.
type ClientAttestationStatusAssurance interface {
	// CheckConfiguration returns nil when the checker's configuration
	// meets level's rules, and otherwise an error saying what falls
	// short.
	CheckConfiguration(level AssuranceLevel) error
}

// VerifiedClientAttestation is a Client Attestation that has verified,
// with its PoP, for ClientAttestationStatusChecker.
type VerifiedClientAttestation struct {
	// Client is the registered client the attestation's sub names.
	Client storage.RegisteredClient

	// Claims is every claim of the verified attestation, each as its
	// raw JSON: "status" (draft-ietf-oauth-status-list), "iss", "sub",
	// "cnf", and any an ecosystem adds (OpenID4VCI's "wallet_name", for
	// instance). A fresh copy for every call, so a checker may keep or
	// change it.
	Claims map[string]json.RawMessage

	// IssuedAt is the attestation's iat, or the zero time when it has
	// none.
	IssuedAt time.Time

	// ExpiresAt is the attestation's exp.
	ExpiresAt time.Time

	// InstanceKey is the RFC 7638 thumbprint of the Client Instance Key
	// (the attestation's cnf key) the PoP verified under.
	InstanceKey string

	// SignerKey is the key the attestation's signature verified with:
	// the leaf certificate's under X5CAttesterChain, the registered
	// attester key under RegisteredAttesterKeys.
	SignerKey crypto.PublicKey

	// SignerCertificates is, under X5CAttesterChain, the certificate
	// chain that verified — with more than one, the first that passed
	// X5CAttesterChain.Revocation: leaf first, ending at the trust anchor, so
	// SignerCertificates[i+1] issued SignerCertificates[i] — the
	// convention of ClientCertificateRevocationCheck.Chain. Nil under
	// RegisteredAttesterKeys.
	SignerCertificates []*x509.Certificate
}

// ErrClientAttestationRevoked is what a ClientAttestationStatusChecker's
// error wraps to refuse an attestation that is no longer valid:
// invalid_client.
var ErrClientAttestationRevoked = errors.New("server: the client attestation is revoked")

// NoClientAttestationStatusCheck explicitly declines checking whether a
// Client Attestation is still valid: an attestation stays accepted until
// it expires, even if its attester has withdrawn it. Right when the
// attesters this server trusts publish no status for their
// attestations, or issue them so short-lived that expiry stands in for
// revocation. Exists so declining under AssuranceProduction, which
// requires Dependencies.ClientAttestationStatus with attestation-based
// client authentication, is a conscious, visible line of code, the same
// reason NoClientCertificateRevocationCheck exists. It fetches nothing,
// so production accepts it, by value or pointer, without a
// ClientAttestationStatusAssurance check; a struct embedding it is a
// checker of its own, and must implement that check itself.
type NoClientAttestationStatusCheck struct{}

// CheckClientAttestationStatus implements ClientAttestationStatusChecker
// by accepting every attestation.
func (NoClientAttestationStatusCheck) CheckClientAttestationStatus(context.Context, VerifiedClientAttestation) error {
	return nil
}

// validateClientAttestationStatus refuses a nil
// *NoClientAttestationStatusCheck.
func validateClientAttestationStatus(checker ClientAttestationStatusChecker) error {
	if p, ok := checker.(*NoClientAttestationStatusCheck); ok && p == nil {
		return errors.New("server: dependencies: client attestation status is a nil *NoClientAttestationStatusCheck")
	}
	return nil
}

// checkClientAttestationStatusConfiguration runs checker's own check of
// its configuration at level, when it implements
// ClientAttestationStatusAssurance.
func checkClientAttestationStatusConfiguration(checker ClientAttestationStatusChecker, level AssuranceLevel) error {
	asserter, ok := checker.(ClientAttestationStatusAssurance)
	if !ok {
		return nil
	}
	if err := asserter.CheckConfiguration(level); err != nil {
		return fmt.Errorf("server: dependencies: client_attestation_status: %w", err)
	}
	return nil
}

// checkProductionClientAttestationStatus refuses, under
// AssuranceProduction with attestation-based client authentication, no
// ClientAttestationStatus at all, and a checker that doesn't check its
// own configuration (ClientAttestationStatusAssurance) unless it is
// NoClientAttestationStatusCheck itself, by value or pointer, which
// fetches nothing. It runs the check of one that does: here rather than
// in validateAttestationDependencies, so a refusal joins the rest of
// production's.
func checkProductionClientAttestationStatus(checker ClientAttestationStatusChecker) error {
	switch checker.(type) {
	case nil:
		return errors.New("server: dependencies: client_attestation_status is required under AssuranceProduction when attestation_based_client_authentication is set (pass a ClientAttestationStatusChecker, or NoClientAttestationStatusCheck{} when your attesters publish no status)")
	case NoClientAttestationStatusCheck, *NoClientAttestationStatusCheck:
		return nil
	}
	if _, ok := checker.(ClientAttestationStatusAssurance); !ok {
		return errors.New("server: dependencies: client_attestation_status must implement server.ClientAttestationStatusAssurance under AssuranceProduction, to check its own configuration: the fetcher it reaches the status-list URIs attestations name with, say")
	}
	return checkClientAttestationStatusConfiguration(checker, AssuranceProduction)
}

// checkAttestationStillValid runs, once an attestation and its PoP have
// verified, the checks that depend on what its attester has withdrawn
// since issuing it: the attester certificate's revocation, under
// X5CAttesterChain, then Dependencies.ClientAttestationStatus, if set.
func (s *Server) checkAttestationStillValid(ctx context.Context, client storage.RegisteredClient, verified clientattestation.VerifiedAttestation, signer attesterSigner, instanceKey string) *Error {
	if signer.revocation != nil {
		passed, revErr := checkChainsRevocation(ctx, signer.revocation, signer.chains, s.deps.Clock.Now())
		if err := revocationError(revErr, "attester certificate"); err != nil {
			return err
		}
		signer.chain = passed
	}
	if s.deps.ClientAttestationStatus == nil {
		return nil
	}
	err := s.deps.ClientAttestationStatus.CheckClientAttestationStatus(ctx, VerifiedClientAttestation{
		Client:             client,
		Claims:             cloneClaims(verified.Claims),
		IssuedAt:           verified.IssuedAt,
		ExpiresAt:          verified.ExpiresAt,
		InstanceKey:        instanceKey,
		SignerKey:          signer.key,
		SignerCertificates: slices.Clone(signer.chain),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrClientAttestationRevoked):
		return newError(ErrorInvalidClient, 401, "client attestation has been revoked", err)
	default:
		return newError(ErrorServerError, 500, "failed to check the client attestation's status", err)
	}
}

// cloneClaims copies claims, values included, so a checker can't change
// what another sees.
func cloneClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		out[name] = bytes.Clone(value)
	}
	return out
}
