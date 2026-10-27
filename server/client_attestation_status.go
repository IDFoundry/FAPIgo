package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
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
// VerifiedClientAttestation carries.
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
	// this one's attestations.
	CheckClientAttestationStatus(ctx context.Context, a VerifiedClientAttestation) error
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
	// chain that verified: leaf first, ending at the trust anchor, so
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
// reason NoClientCertificateRevocationCheck exists.
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

// checkProductionClientAttestationStatus refuses, under
// AssuranceProduction with attestation-based client authentication, no
// ClientAttestationStatus at all.
func checkProductionClientAttestationStatus(checker ClientAttestationStatusChecker) error {
	if checker == nil {
		return errors.New("server: dependencies: client_attestation_status is required under AssuranceProduction when attestation_based_client_authentication is set (pass a ClientAttestationStatusChecker, or NoClientAttestationStatusCheck{} when your attesters publish no status)")
	}
	return nil
}

// checkAttestationStillValid runs, once an attestation and its PoP have
// verified, the checks that depend on what its attester has withdrawn
// since issuing it: the attester certificate's revocation, under
// X5CAttesterChain, then Dependencies.ClientAttestationStatus, if set.
func (s *Server) checkAttestationStillValid(ctx context.Context, client storage.RegisteredClient, verified clientattestation.VerifiedAttestation, signer attesterSigner, instanceKey string) *Error {
	if signer.revocation != nil {
		check := ClientCertificateRevocationCheck{Chain: slices.Clone(signer.chain), Now: s.deps.Clock.Now()}
		if err := signer.revocation.CheckRevocation(ctx, check); err != nil {
			return newError(ErrorInvalidClient, 401, "attester certificate is revoked or its revocation status is unknown", err)
		}
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
