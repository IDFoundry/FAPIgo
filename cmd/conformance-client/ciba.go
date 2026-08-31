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
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
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
// mtls selects storage.SenderConstrainMTLS instead of the default DPoP
// binding — see mtls.go's own package doc comment for why this exists.
func runCIBA(apiBase string, mtls bool) error {
	ctx := context.Background()

	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAuthentication: fapi.ES256, keys.BackchannelAuthenticationRequestSigning: fapi.ES256,
	}
	var rawHTTP *http.Client
	var clientCertPEM string
	if mtls {
		clientCert, err := selfSignedClientCert("gofapi-ciba-mtls-driver")
		if err != nil {
			return fmt.Errorf("generate client certificate: %w", err)
		}
		rawHTTP = mtlsSuiteHTTPClient(clientCert)
		// EnsureClientCertificateMatches (net/openid/conformance/condition/as)
		// compares the certificate actually presented on the connection
		// against a "client.certificate" value read straight out of this
		// plan's own static config (GetStaticClientConfiguration/
		// configureClient) — there is no other mechanism that registers
		// it (confirmed by disassembling both, not assumed): an omitted
		// "client.certificate" fails every mTLS-authenticated request
		// with "Couldn't find registered client certificate", and a
		// module that never gets past that check never reaches a
		// terminal state at all, no matter how long this driver waits.
		clientCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Certificate[0]}))
	} else {
		purposes[keys.DPoPProofSigning] = fapi.ES256
		rawHTTP = insecureSuiteHTTPClient()
	}

	keyMgr, err := ephemeral.NewKeyManager(purposes)
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}

	jwks, err := ephemeralJWKS(ctx, keyMgr,
		keys.ClientAuthentication, keys.BackchannelAuthenticationRequestSigning)
	if err != nil {
		return fmt.Errorf("build client jwks: %w", err)
	}

	suffix := randomSuffix()
	alias := "gofapi-ciba-driver-" + suffix
	// clientID must vary per run exactly like alias does: an mTLS run's
	// per-module client-certificate registration is keyed by client_id,
	// not by alias — a fixed client_id here left an orphaned module
	// instance from a killed/still-finishing earlier run (its own
	// certificate registration not yet torn down) able to corrupt a
	// fresh run's own registration under the same client_id, surfacing
	// as spurious EnsureClientCertificateMatches failures and alias
	// conflicts unrelated to anything this run's own driver code did
	// (confirmed live, not assumed — traced via the suite's own module
	// log after two back-to-back -mtls runs).
	clientID := "gofapi-ciba-driver-client-" + suffix

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

	clientConfig := map[string]any{
		"client_id": clientID,
		"scope":     cibaScope,
		"jwks": map[string]any{
			"keys": jwks,
		},
	}
	if clientCertPEM != "" {
		clientConfig["certificate"] = clientCertPEM
	}
	planConfig, err := json.Marshal(map[string]any{
		"alias": alias,
		"server": map[string]any{
			"jwks": map[string]any{
				"keys": []any{ecdsaPrivateJWK(serverKey, "gofapi-ciba-driver-server-key")},
			},
		},
		"client": clientConfig,
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

	d := cibaModuleDriver{HTTP: rawHTTP, APIBase: apiBase, PlanID: planID, ClientID: clientID, Keys: keyMgr, MTLS: mtls}
	summary := make(map[string]string, len(moduleNames))
	for i, name := range moduleNames {
		log.Printf("--- [%d/%d] %s ---", i+1, len(moduleNames), name)
		outcome := runCIBAModule(ctx, d, name)
		summary[name] = outcome
		log.Printf("[%d/%d] %s: %s", i+1, len(moduleNames), name, outcome)
	}

	log.Printf("=== summary ===")
	for _, name := range moduleNames {
		log.Printf("%-16s %s", summary[name], name)
	}
	return nil
}

// cibaModuleDriver holds everything runCIBAModule needs that stays
// fixed across every module in a single CIBA plan run — mirrors
// moduleDriver's own shape in main.go for the identical go:S107
// reason: only the module's own test name varies per call.
type cibaModuleDriver struct {
	HTTP     *http.Client
	APIBase  string
	PlanID   string
	ClientID string
	Keys     *ephemeral.KeyManager
	MTLS     bool
}

// runCIBAModule drives testName through discover -> begin backchannel
// authentication -> poll (bounded by cibaMaxPolls, spaced by whatever
// interval the module's own response carried) -> awaitVerdict. Polling
// itself lives in pollCIBABackchannelAuthentication, split out purely
// to keep this method's own setup/poll phases readable (go:S3776).
func runCIBAModule(ctx context.Context, d cibaModuleDriver, testName string) string {
	rawHTTP, apiBase, planID, clientID, keyMgr, mtls := d.HTTP, d.APIBase, d.PlanID, d.ClientID, d.Keys, d.MTLS
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
		return awaitVerdict(rawHTTP, apiBase, module.ID, "discover issuer metadata: "+err.Error()).String()
	}
	if len(discovered.IDTokenAlgorithms) == 0 {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer advertises no recognized ID token signing algorithm").String()
	}
	if discovered.Endpoints.BackchannelAuthentication.IsZero() {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer does not advertise a backchannel_authentication_endpoint").String()
	}
	if !containsES256(discovered.BackchannelAuthenticationRequestAlgorithms) {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer does not advertise ES256 as a backchannel authentication request signing algorithm").String()
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
		SenderConstrain: storage.SenderConstrainDPoP,
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
	if mtls {
		cfg.SenderConstrain = storage.SenderConstrainMTLS
		if err := applyMTLSEndpointAliases(&cfg, discovered); err != nil {
			return awaitVerdict(rawHTTP, apiBase, module.ID, err.Error()).String()
		}
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
		return awaitVerdict(rawHTTP, apiBase, module.ID, "begin backchannel authentication: "+err.Error()).String()
	}

	return pollCIBABackchannelAuthentication(ctx, cl, session, rawHTTP, apiBase, module.ID)
}

// pollCIBABackchannelAuthentication polls session (bounded by
// cibaMaxPolls, spaced by whatever interval the module's own response
// carried) until it's approved, denied, or expired — split out of
// runCIBAModule purely to keep that method's own setup/poll phases
// readable (go:S3776).
func pollCIBABackchannelAuthentication(ctx context.Context, cl *client.Client, session client.BackchannelAuthenticationSession, rawHTTP *http.Client, apiBase, moduleID string) string {
	interval := session.Interval()
	for attempt := 0; attempt < cibaMaxPolls; attempt++ {
		time.Sleep(interval)
		result, err := cl.PollBackchannelAuthentication(ctx, session)
		if err != nil {
			return awaitVerdict(rawHTTP, apiBase, moduleID, "poll backchannel authentication: "+err.Error()).String()
		}
		switch r := result.(type) {
		case client.BackchannelAuthenticationPending:
			if r.SlowDown {
				interval += 5 * time.Second // RFC 8628's own convention
			}
			continue
		case client.BackchannelAuthenticationDenied:
			return awaitVerdict(rawHTTP, apiBase, moduleID, "").String()
		case client.BackchannelAuthenticationExpired:
			return awaitVerdict(rawHTTP, apiBase, moduleID, "").String()
		case client.BackchannelAuthenticationApproved:
			// Mirrors runModule's own accounts-endpoint call
			// (main.go): FAPICIBARPProfileBehavior's own
			// getAccountsEndpointResponseSteps requires the RP to
			// call the "accounts" resource endpoint with the
			// issued access token before this module reaches a
			// terminal state at all — a module that gets its
			// tokens but never places this call sits in WAITING
			// indefinitely (confirmed live: still WAITING after
			// 45s with a fully successful token exchange already
			// logged). Discovered exactly the same way as
			// runModule's own version: the URL isn't part of OIDC
			// discovery, only this "exported value" mechanism.
			if err := callAccountsEndpoint(ctx, cl, rawHTTP, apiBase, moduleID, r.Tokens); err != nil {
				return "ERROR: call accounts endpoint: " + err.Error()
			}
			return awaitVerdict(rawHTTP, apiBase, moduleID, "").String()
		}
	}
	return awaitVerdict(rawHTTP, apiBase, moduleID, "gave up polling after "+fmt.Sprint(cibaMaxPolls)+" attempts").String()
}
