// This file drives the OIDF suite's FAPI-CIBA-ID1 RP (client) test
// plan (fapi-ciba-id1-client-test-plan) through client's CIBA support
// (BeginBackchannelAuthentication/PollBackchannelAuthentication).
//
// Unlike the browser-redirect plans in main.go, this plan has no
// browser hop to intercept at all — the RP calls the suite's mock AS's
// backchannel-authenticate endpoint directly, then polls its token
// endpoint on its own schedule — so runModule's shape doesn't apply
// here; runCIBA below drives its own, CIBA-specific sequence per
// module.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
)

const (
	cibaPlanName = "fapi-ciba-id1-client-test-plan"

	// cibaScope must match cibaPlanConfig's own "client.scope" exactly
	// (disregarding order) — the suite's own
	// EnsureRequestedScopeIsEqualToConfiguredScopeDisregardingOrder
	// condition checks this on every module.
	cibaScope = "openid"

	// cibaLoginHint is sent as the backchannel authentication request's
	// login_hint claim. Its value is unconstrained under fapi_ciba_profile
	// plain_fapi (the profile this driver targets) — the suite only
	// requires exactly one hint parameter be present, not that it equal
	// anything specific (unlike openbanking_brazil's
	// EnsureLoginHintEqualsConsentId, which this driver doesn't target).
	cibaLoginHint = "gofapi-ciba-driver-user"

	// cibaMaxPolls bounds how many times this driver polls the token
	// endpoint for one module before giving up — the happy-path module's
	// own default interval is 5 seconds (SetIntervalTo5Seconds), so this
	// generously covers a real approval/ping delay without polling
	// forever if a module never resolves.
	cibaMaxPolls = 6
)

// ecdsaPrivateJWK encodes priv (assumed P-256, matching every key this
// driver generates) as a full private EC JWK map — the shape a suite
// plan config's "server.jwks" field needs (see runCIBA's own comment
// on why this is required here but nowhere else in this driver). This
// is deliberately separate from internal/jose.NewJWK, which only ever
// encodes a public key: this module's own KeyManager abstraction never
// needs to export private key material, since it signs on a caller's
// behalf instead — this one case is different because the private key
// here belongs to the suite's own mock AS, a role this driver
// configures but never signs anything as.
func ecdsaPrivateJWK(priv *ecdsa.PrivateKey, kid string) map[string]any {
	size := (priv.Curve.Params().BitSize + 7) / 8
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, size))),
		"y":   base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, size))),
		"d":   base64.RawURLEncoding.EncodeToString(priv.D.FillBytes(make([]byte, size))),
		"use": "sig",
		"alg": "ES256",
		"kid": kid,
	}
}

// cibaVariant selects the same "plain FAPI, poll mode, private_key_jwt"
// shape the AS-side CIBA plan (conformance/server) already targets —
// see conformance/server/oidf-config/README.md's own ciba-plan.json.
var cibaVariant = map[string]string{
	"client_auth_type":  "private_key_jwt",
	"fapi_ciba_profile": "plain_fapi",
	"ciba_mode":         "poll",
}

// runCIBA drives every module of the FAPI-CIBA-ID1 RP test plan through
// client.BeginBackchannelAuthentication/PollBackchannelAuthentication.
func runCIBA(apiBase string) error {
	ctx := context.Background()
	rawHTTP := insecureSuiteHTTPClient()

	keyMgr, err := newEphemeralKeyManager([]keys.SigningPurpose{
		keys.ClientAuthentication, keys.DPoPProofSigning, keys.BackchannelAuthenticationRequestSigning,
	})
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}

	jwks, err := ephemeralJWKS(ctx, keyMgr,
		keys.ClientAuthentication, keys.BackchannelAuthenticationRequestSigning)
	if err != nil {
		return fmt.Errorf("build client jwks: %w", err)
	}

	alias := "gofapi-ciba-driver-" + randomSuffix()
	clientID := "gofapi-ciba-driver-client"

	// Unlike the browser-redirect plans (main.go), whose own
	// GenerateServerConfiguration auto-generates the mock AS's signing
	// key, this plan's LoadServerJWKs condition requires the plan
	// config to supply "server.jwks" explicitly (confirmed live: an
	// omitted server.jwks fails every module immediately with
	// "LoadServerJWKs: Couldn't find a JWK set in configuration",
	// before the module ever reaches WAITING) — see the sample RP
	// config the suite repo itself ships,
	// scripts/test-configs-rp-against-op/fapi-ciba-rp-test-config.json.
	// This key is the mock AS's own signing key, never this driver's;
	// it plays no role beyond satisfying that one requirement.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate mock AS server key: %w", err)
	}

	planConfig, err := json.Marshal(map[string]any{
		"alias": alias,
		"server": map[string]any{
			"jwks": map[string]any{
				"keys": []any{ecdsaPrivateJWK(serverKey, "gofapi-ciba-driver-server-key")},
			},
		},
		"client": map[string]any{
			"client_id": clientID,
			"scope":     cibaScope,
			"jwks": map[string]any{
				"keys": jwks,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal plan config: %w", err)
	}

	planID, moduleNames, err := createPlan(rawHTTP, apiBase, cibaPlanName, cibaVariant, planConfig)
	if err != nil {
		return fmt.Errorf("create plan: %w", err)
	}
	log.Printf("created plan %s (alias %s), %d modules", planID, alias, len(moduleNames))
	log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)

	summary := make(map[string]string, len(moduleNames))
	for i, name := range moduleNames {
		log.Printf("--- [%d/%d] %s ---", i+1, len(moduleNames), name)
		outcome := runCIBAModule(ctx, rawHTTP, apiBase, planID, clientID, keyMgr, name)
		summary[name] = outcome
		log.Printf("[%d/%d] %s: %s", i+1, len(moduleNames), name, outcome)
	}

	log.Printf("=== summary ===")
	for _, name := range moduleNames {
		log.Printf("%-16s %s", summary[name], name)
	}
	return nil
}

// runCIBAModule drives testName through discover -> begin backchannel
// authentication -> poll (bounded by cibaMaxPolls, spaced by whatever
// interval the module's own response carried) -> awaitVerdict.
func runCIBAModule(ctx context.Context, rawHTTP *http.Client, apiBase, planID, clientID string, keyMgr *ephemeralKeyManager, testName string) string {
	module, err := createModuleInstance(rawHTTP, apiBase, planID, testName)
	if err != nil {
		return "ERROR: create module instance: " + err.Error()
	}

	if err := waitUntilWaiting(rawHTTP, apiBase, module.ID, 10*time.Second); err != nil {
		return "ERROR: wait for module ready: " + err.Error()
	}

	issuer, err := fapi.ParseIssuerURL(module.URL + "/")
	if err != nil {
		return "ERROR: parse issuer URL: " + err.Error()
	}

	fetcher, err := fapihttp.New(rawHTTP, fapihttp.Config{
		MaxResponseBytes:  1 << 20,
		RequestTimeout:    fetchTimeout,
		MaxRedirects:      5,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		return "ERROR: build fetcher: " + err.Error()
	}

	discovered, err := client.Discover(ctx, fetcher, issuer)
	if err != nil {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "discover issuer metadata: "+err.Error())
	}
	if len(discovered.IDTokenAlgorithms) == 0 {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer advertises no recognized ID token signing algorithm")
	}
	if discovered.Endpoints.BackchannelAuthentication.IsZero() {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer does not advertise a backchannel_authentication_endpoint")
	}
	if !containsES256(discovered.BackchannelAuthenticationRequestAlgorithms) {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer does not advertise ES256 as a backchannel authentication request signing algorithm")
	}

	issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, discovered.JWKSURI, jwksCacheTTL)
	if err != nil {
		return "ERROR: build issuer key source: " + err.Error()
	}

	cfg := client.Config{
		Issuer:    issuer,
		ClientID:  fapi.ClientID(clientID),
		Endpoints: discovered.Endpoints,
		Profile:   client.ProfileFAPISecurity,
		Algorithms: client.Algorithms{
			ClientAuthentication:             fapi.ES256,
			DPoP:                             fapi.ES256,
			IDToken:                          discovered.IDTokenAlgorithms[0],
			BackchannelAuthenticationRequest: fapi.ES256,
		},
		Limits: client.Limits{
			ClientAssertionLifetime:                  time.Minute,
			SessionLifetime:                          5 * time.Minute,
			MaxIDTokenLifetime:                       5 * time.Minute,
			MaxClockSkew:                             15 * time.Second,
			HTTPTimeout:                              fetchTimeout,
			MaxHTTPResponseBytes:                     1 << 20,
			MaxJOSECompactBytes:                      16 * 1024,
			BackchannelAuthenticationRequestLifetime: time.Minute,
		},
	}
	deps := client.Dependencies{
		Sessions:   newMemSessionStore(),
		Keys:       keyMgr,
		IssuerKeys: issuerKeys,
		HTTP:       rawHTTP,
		Clock:      client.SystemClock{},
		Random:     rand.Reader,
	}

	cl, err := client.New(cfg, deps)
	if err != nil {
		return "ERROR: construct client: " + err.Error()
	}

	session, err := cl.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope: []string{cibaScope}, LoginHint: cibaLoginHint,
	})
	if err != nil {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "begin backchannel authentication: "+err.Error())
	}

	interval := session.Interval()
	for attempt := 0; attempt < cibaMaxPolls; attempt++ {
		time.Sleep(interval)
		result, err := cl.PollBackchannelAuthentication(ctx, session)
		if err != nil {
			return awaitVerdict(rawHTTP, apiBase, module.ID, "poll backchannel authentication: "+err.Error())
		}
		switch r := result.(type) {
		case client.BackchannelAuthenticationPending:
			if r.SlowDown {
				interval += 5 * time.Second // RFC 8628's own convention
			}
			continue
		case client.BackchannelAuthenticationDenied:
			return awaitVerdict(rawHTTP, apiBase, module.ID, "")
		case client.BackchannelAuthenticationExpired:
			return awaitVerdict(rawHTTP, apiBase, module.ID, "")
		case client.BackchannelAuthenticationApproved:
			_ = r.Tokens
			return awaitVerdict(rawHTTP, apiBase, module.ID, "")
		}
	}
	return awaitVerdict(rawHTTP, apiBase, module.ID, "gave up polling after "+fmt.Sprint(cibaMaxPolls)+" attempts")
}
