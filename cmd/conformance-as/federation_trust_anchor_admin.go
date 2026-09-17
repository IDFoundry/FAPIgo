package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// dynamicFederationClients wraps a swappable federation.AutomaticClientRepository/
// AutomaticClientKeySource pair so -federation-trust-anchor-admin's own
// POST /internal/federation/trust-anchors can add a new Trust Anchor at
// runtime, without restarting this binary. A real restart would also
// regenerate this binary's own ephemeral federation signing key
// (keys/ephemeral) — invalidating any Entity Statement a peer already
// cached from before the restart — so it isn't a substitute for this,
// even setting aside the downtime.
//
// Exists only when the flag is set: a real deployment has no business
// letting any caller add a permanently-trusted federation root at
// runtime. The one legitimate use is a conformance run against the
// OIDF suite's own self-hosted Trust Anchor for its "Entity joined to
// test federation OP/RP" plans — its Entity Identifier is generated
// fresh per test instance (a random path segment under the suite's own
// base URL), so no static -federation config file can list it in
// advance.
//
// rebuild also rebuilds the outbound *http.Client itself on every
// call, not just the Resolver — two things a fixed, once-at-startup
// client can't provide, both found by tracing a live run against the
// OIDF suite all the way to a successful PAR call:
//
//  1. fapihttp.Config.AllowedPrivateHosts must be exactly the current
//     trust anchors' own hosts, not a fixed set — the Trust Anchor's
//     own host being allowed isn't enough, since resolving any subject
//     under it (the suite's own self-hosted Relying Party, in this
//     case) starts by fetching that subject's own Entity Configuration,
//     at the identical host.
//  2. TLS verification for that same host needs an exception — see
//     peerTLSConfig's own doc comment for why a fixed pinned cert
//     (this binary's own peer cert, used for its one real, named peer
//     conformance-federation-trust-anchor) can't also cover the
//     suite's own, completely separate self-signed cert.
type dynamicFederationClients struct {
	underlyingClients storage.ClientRepository
	underlyingKeys    keys.ClientKeySource
	peerCertPool      *x509.CertPool // nil under -insecure-http, where there's no TLS to verify at all
	httpTimeout       time.Duration
	fetcherCfg        fapihttp.Config // template: every field except AllowedPrivateHosts, which rebuild computes itself
	limits            federation.Limits
	autoCfg           federation.AutomaticRegistrationConfig
	clock             federation.Clock

	mu           sync.RWMutex
	trustAnchors []federation.TrustAnchor
	repo         *federation.AutomaticClientRepository
	clientKeys   *federation.AutomaticClientKeySource
}

// newDynamicFederationClients validates its arguments, builds the
// initial Resolver/AutomaticClientRepository/AutomaticClientKeySource
// from initial, and returns a dynamicFederationClients ready to serve
// ResolveClient/ResolveVerificationKeys immediately. fetcherCfg's own
// AllowedPrivateHosts is ignored — rebuild always computes it fresh
// from the current trust anchor set.
func newDynamicFederationClients(initial []federation.TrustAnchor, underlyingClients storage.ClientRepository, underlyingKeys keys.ClientKeySource, peerCertPool *x509.CertPool, httpTimeout time.Duration, fetcherCfg fapihttp.Config, limits federation.Limits, autoCfg federation.AutomaticRegistrationConfig, clock federation.Clock) (*dynamicFederationClients, error) {
	d := &dynamicFederationClients{
		underlyingClients: underlyingClients, underlyingKeys: underlyingKeys,
		peerCertPool: peerCertPool, httpTimeout: httpTimeout, fetcherCfg: fetcherCfg,
		limits: limits, autoCfg: autoCfg, clock: clock,
	}
	if err := d.rebuild(initial); err != nil {
		return nil, err
	}
	return d, nil
}

// rebuild constructs a fresh *http.Client + fapihttp.Client
// (AllowedPrivateHosts, and the peerTLSConfig verification exception,
// both set to exactly trustAnchors' own hosts) and a fresh Resolver/
// AutomaticClientRepository/AutomaticClientKeySource trio built on it,
// then atomically swaps them in — every in-flight ResolveClient/
// ResolveVerificationKeys call still sees a self-consistent fetcher+
// repo+clientKeys triple from the same build, never pieces from
// different builds mixed together.
func (d *dynamicFederationClients) rebuild(trustAnchors []federation.TrustAnchor) error {
	allowedPrivateHosts := make([]string, 0, len(trustAnchors))
	for _, ta := range trustAnchors {
		host, err := hostOf(ta.EntityID)
		if err != nil {
			return fmt.Errorf("trust anchor entity id %q: %w", ta.EntityID, err)
		}
		allowedPrivateHosts = append(allowedPrivateHosts, host)
	}
	httpClient := &http.Client{Timeout: d.httpTimeout}
	if d.peerCertPool != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: peerTLSConfig(d.peerCertPool, allowedPrivateHosts)}
	}
	cfg := d.fetcherCfg
	cfg.AllowedPrivateHosts = allowedPrivateHosts
	fetcher, err := fapihttp.New(httpClient, cfg)
	if err != nil {
		return fmt.Errorf("build fetcher: %w", err)
	}
	resolver, err := federation.NewResolver(federation.Config{TrustAnchors: trustAnchors, Limits: d.limits}, federation.Dependencies{HTTP: fetcher, Clock: d.clock})
	if err != nil {
		return fmt.Errorf("build resolver: %w", err)
	}
	repo, err := federation.NewAutomaticClientRepository(d.underlyingClients, resolver, fetcher, d.autoCfg, d.clock)
	if err != nil {
		return fmt.Errorf("build automatic client repository: %w", err)
	}
	clientKeys, err := federation.NewAutomaticClientKeySource(d.underlyingKeys, repo)
	if err != nil {
		return fmt.Errorf("build automatic client key source: %w", err)
	}
	d.mu.Lock()
	d.trustAnchors = trustAnchors
	d.repo = repo
	d.clientKeys = clientKeys
	d.mu.Unlock()
	return nil
}

// hostOf extracts the hostname (no port) from rawURL — unlike
// cmd/conformance-federation-trust-anchor's own mustHost, a malformed
// entity_id here comes from an HTTP request body
// (federationTrustAnchorAdminHandler), not fixed operator config, so
// this returns an error instead of exiting the process.
func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("no hostname in %q", rawURL)
	}
	return u.Hostname(), nil
}

// AddTrustAnchor adds ta to the current set, rebuilding and atomically
// swapping in the underlying Resolver/AutomaticClientRepository/
// AutomaticClientKeySource. Idempotent: adding an entity_id that's
// already trusted is a no-op, not an error — safe for an orchestration
// script to retry.
func (d *dynamicFederationClients) AddTrustAnchor(ta federation.TrustAnchor) error {
	d.mu.RLock()
	current := append([]federation.TrustAnchor(nil), d.trustAnchors...)
	d.mu.RUnlock()
	for _, existing := range current {
		if existing.EntityID == ta.EntityID {
			return nil
		}
	}
	return d.rebuild(append(current, ta))
}

// ResolveClient implements storage.ClientRepository.
func (d *dynamicFederationClients) ResolveClient(ctx context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	d.mu.RLock()
	repo := d.repo
	d.mu.RUnlock()
	return repo.ResolveClient(ctx, id)
}

// ResolveVerificationKeys implements keys.ClientKeySource.
func (d *dynamicFederationClients) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	d.mu.RLock()
	clientKeys := d.clientKeys
	d.mu.RUnlock()
	return clientKeys.ResolveVerificationKeys(ctx, req)
}

// addTrustAnchorRequest is POST /internal/federation/trust-anchors' own
// request body shape — deliberately minimal, matching
// federation.TrustAnchor's own two fields.
type addTrustAnchorRequest struct {
	EntityID string          `json:"entity_id"`
	JWKS     json.RawMessage `json:"jwks"`
}

// federationTrustAnchorAdminHandler serves POST /internal/federation/trust-anchors
// — see dynamicFederationClients' own doc comment for why this exists
// and when. Deliberately unauthenticated: gated entirely behind
// -federation-trust-anchor-admin, itself meant only for a trusted
// conformance-run orchestration script reaching this binary over the
// same docker-compose network, never exposed to the internet — the
// same posture -ciba-approval-ui-token's own doc comment describes for
// a differently-shaped debug endpoint.
func federationTrustAnchorAdminHandler(clients *dynamicFederationClients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req addTrustAnchorRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
			return
		}
		if req.EntityID == "" {
			http.Error(w, "entity_id is required", http.StatusBadRequest)
			return
		}
		if len(req.JWKS) == 0 {
			http.Error(w, "jwks is required", http.StatusBadRequest)
			return
		}
		if err := clients.AddTrustAnchor(federation.TrustAnchor{EntityID: req.EntityID, JWKS: req.JWKS}); err != nil {
			http.Error(w, fmt.Sprintf("add trust anchor: %v", err), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
