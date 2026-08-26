// Command conformance-client drives this module's client package
// through every module of a FAPI2 relying-party conformance test plan
// against a locally running OIDF conformance suite, entirely
// headlessly: it plays both the RP under test (via the client package)
// and the "browser" that carries requests between the RP and the
// suite's mock authorization server, since neither role here needs a
// human or a real browser — the suite's mock AS doesn't render an
// interactive consent page for a private_key_jwt+DPoP RP test, and this
// driver's own HTTP client can intercept the authorization redirect
// itself.
//
// Every module gets the exact same driving logic: discover, begin
// authorization, follow the redirect, complete authorization, then call
// the profile's resource ("accounts") endpoint if a token was actually
// issued. For most of the plan's negative-test modules that's
// deliberately the right shape too — the suite expects the client to
// detect a problem (a bad iss, a missing nonce, ...) and stop somewhere
// in that same sequence, which surfaces here as an ordinary Go error
// this driver logs and moves past rather than treats as fatal. The
// suite's own per-module grading (fetched via /api/info after a short
// grace period) is the actual verdict — this driver's own error or lack
// of one is never authoritative — see conformance/client/scripts/README.md.
//
// Usage:
//
//	go run ./cmd/conformance-client -profile=baseline
//	go run ./cmd/conformance-client -profile=message-signing
//
// -profile selects which plan to run (see the profiles map below);
// baseline is the default. With no -suite flag it talks to the suite's
// default local dev-mode address, https://localhost.emobix.co.uk:8443/
// — the same instance conformance/server's own scripts target.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

const (
	fetchTimeout = 15 * time.Second
	jwksCacheTTL = time.Minute
)

// driverProfile is everything that differs between the plans this
// driver knows how to run: which suite plan/variant selects it, and
// which client.Profile (and supporting key material) it needs.
type driverProfile struct {
	planName          string
	variant           map[string]string
	clientProfile     client.Profile
	signRequestObject bool
}

var profiles = map[string]driverProfile{
	"baseline": {
		planName: "fapi2-security-profile-final-client-test-plan",
		variant: map[string]string{
			"client_auth_type": "private_key_jwt",
			"sender_constrain": "dpop",
			"fapi_profile":     "plain_fapi",
			"fapi_client_type": "oidc",
		},
		clientProfile: client.ProfileFAPISecurity,
	},
	"message-signing": {
		planName: "fapi2-message-signing-final-client-test-plan",
		variant: map[string]string{
			"client_auth_type":    "private_key_jwt",
			"sender_constrain":    "dpop",
			"fapi_profile":        "plain_fapi",
			"fapi_client_type":    "oidc",
			"fapi_request_method": "signed_non_repudiation",
			"fapi_response_mode":  "jarm",
		},
		clientProfile:     client.ProfileFAPISecurityWithMessageSigning,
		signRequestObject: true,
	},
}

func main() {
	apiBase := flag.String("suite", "https://localhost.emobix.co.uk:8443/", "conformance suite base URL")
	profileName := flag.String("profile", "baseline", "which client test plan to run: baseline or message-signing")
	flag.Parse()

	profile, ok := profiles[*profileName]
	if !ok {
		log.Fatalf("conformance-client: unknown -profile %q (want baseline or message-signing)", *profileName)
	}

	if err := run(*apiBase, profile); err != nil {
		log.Fatalf("conformance-client: %v", err)
	}
}

// insecureSuiteHTTPClient trusts any TLS certificate, matching every
// other local script in this repo that talks to the suite's dev-mode
// instance (see conformance/server/docker-compose.yml's header comment)
// — never appropriate outside a local conformance run.
func insecureSuiteHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
}

func run(apiBase string, profile driverProfile) error {
	ctx := context.Background()
	rawHTTP := insecureSuiteHTTPClient()

	purposes := []keys.SigningPurpose{keys.ClientAuthentication, keys.DPoPProofSigning}
	if profile.signRequestObject {
		purposes = append(purposes, keys.RequestObjectSigning)
	}
	keyMgr, err := newEphemeralKeyManager(purposes)
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}
	// This driver's own client.Client instances aren't constructed here —
	// each module discovers its own mock-AS URL and only then builds one,
	// deep inside runModule — so there's no single client.Client yet to
	// call PublicJWKS on for the plan config the suite needs up front.
	// jose.NewJWK is the same underlying encoding PublicJWKS itself uses;
	// this package is inside the module, so it can reach it directly
	// rather than hand-rolling JWK encoding a second time.
	clientAuthPub, err := keyMgr.PublicKey(ctx, keys.ClientAuthentication, fapi.ES256)
	if err != nil {
		return fmt.Errorf("read client authentication public key: %w", err)
	}
	clientAuthJWK, err := jose.NewJWK(clientAuthPub.PublicKey, fapi.ES256)
	if err != nil {
		return fmt.Errorf("build client authentication jwk: %w", err)
	}
	jwks := []any{clientAuthJWK.WithKeyID(clientAuthPub.KeyID)}

	if profile.signRequestObject {
		reqObjPub, err := keyMgr.PublicKey(ctx, keys.RequestObjectSigning, fapi.ES256)
		if err != nil {
			return fmt.Errorf("read request object signing public key: %w", err)
		}
		reqObjJWK, err := jose.NewJWK(reqObjPub.PublicKey, fapi.ES256)
		if err != nil {
			return fmt.Errorf("build request object signing jwk: %w", err)
		}
		jwks = append(jwks, reqObjJWK.WithKeyID(reqObjPub.KeyID))
	}

	alias := "gofapi-rp-driver-" + randomSuffix()
	clientID := "gofapi-rp-driver-client"
	redirectURI := apiBase + "test/a/" + alias + "/callback"

	planConfig, err := json.Marshal(map[string]any{
		"alias": alias,
		"client": map[string]any{
			"client_id":    clientID,
			"scope":        "openid",
			"redirect_uri": redirectURI,
			"jwks": map[string]any{
				"keys": jwks,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal plan config: %w", err)
	}

	planID, moduleNames, err := createPlan(rawHTTP, apiBase, profile.planName, profile.variant, planConfig)
	if err != nil {
		return fmt.Errorf("create plan: %w", err)
	}
	log.Printf("created plan %s (alias %s), %d modules", planID, alias, len(moduleNames))
	log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)

	driver := moduleDriver{
		HTTP: rawHTTP, APIBase: apiBase, PlanID: planID,
		ClientID: clientID, RedirectURI: redirectURI, Keys: keyMgr, Profile: profile,
	}
	summary := make(map[string]string, len(moduleNames))
	for i, name := range moduleNames {
		log.Printf("--- [%d/%d] %s ---", i+1, len(moduleNames), name)
		outcome := runModule(ctx, driver, name)
		summary[name] = outcome
		log.Printf("[%d/%d] %s: %s", i+1, len(moduleNames), name, outcome)
	}

	log.Printf("=== summary ===")
	for _, name := range moduleNames {
		log.Printf("%-16s %s", summary[name], name)
	}
	return nil
}

// moduleDriver holds everything runModule needs that stays fixed across
// every module in a single plan run — run's own loop builds one of
// these once, before iterating moduleNames, since only the module's own
// test name varies per call.
type moduleDriver struct {
	HTTP        *http.Client
	APIBase     string
	PlanID      string
	ClientID    string
	RedirectURI string
	Keys        *ephemeralKeyManager
	Profile     driverProfile
}

// runModule drives testName through the same discover/authorize/token/
// resource sequence every module in this plan needs, and returns a
// short human-readable outcome string rather than an error: for most of
// this plan's modules, this driver's own step failing partway through
// (a rejected ID token, a denied callback, ...) is the module's whole
// point, not a bug in the driver, so there is nothing here for a caller
// to usefully treat as fatal. The suite's own graded result — fetched
// separately, after a grace period, back in run — is what actually
// matters.
func runModule(ctx context.Context, d moduleDriver, testName string) string {
	rawHTTP, apiBase, planID, clientID, redirectURI, keyMgr, profile := d.HTTP, d.APIBase, d.PlanID, d.ClientID, d.RedirectURI, d.Keys, d.Profile
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
		MaxResponseBytes: 1 << 20,
		RequestTimeout:   fetchTimeout,
		MaxRedirects:     5,
		// This driver only ever talks to a locally running OIDF
		// conformance suite (see the package doc comment) — its
		// discovery/JWKS fetches always target a loopback-resolving
		// host (localhost.emobix.co.uk by default), so fapihttp's
		// pre-dial SSRF check needs this to permit it.
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

	issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, discovered.JWKSURI, jwksCacheTTL)
	if err != nil {
		return "ERROR: build issuer key source: " + err.Error()
	}

	algorithms := client.Algorithms{
		ClientAuthentication: fapi.ES256,
		DPoP:                 fapi.ES256,
		IDToken:              discovered.IDTokenAlgorithms[0],
	}
	limits := client.Limits{
		ClientAssertionLifetime: time.Minute,
		SessionLifetime:         5 * time.Minute,
		MaxIDTokenLifetime:      5 * time.Minute,
		MaxClockSkew:            15 * time.Second,
		HTTPTimeout:             fetchTimeout,
		MaxHTTPResponseBytes:    1 << 20,
	}
	if profile.signRequestObject {
		// This driver's key manager only ever generates ES256 keys, so it
		// must specifically pick ES256 out of the issuer's advertised
		// algorithm list rather than blindly take index 0 — the suite
		// lists PS256 first, which this driver has no RSA key to sign
		// with (confirmed live: taking [0] failed every module with
		// "PS256 signer must use an RSA key, got *ecdsa.PublicKey").
		if !containsES256(discovered.RequestObjectAlgorithms) {
			return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer does not advertise ES256 as a request object signing algorithm")
		}
		if len(discovered.JARMAlgorithms) == 0 {
			return awaitVerdict(rawHTTP, apiBase, module.ID, "issuer advertises no recognized JARM signing algorithm")
		}
		algorithms.RequestObject = fapi.ES256
		algorithms.JARM = discovered.JARMAlgorithms[0]
		limits.RequestObjectLifetime = time.Minute
		// The suite's own JARM responses carry a 10-minute exp
		// (GenerateJARMResponseClaims.java: "Instant.now().plusSeconds(600)"
		// — confirmed by reading the suite's source directly after a
		// too-tight 5-minute limit here rejected every legitimate
		// response with "jarm: exp exceeds maximum allowed lifetime").
		limits.MaxJARMResponseLifetime = 15 * time.Minute
	}

	cfg := client.Config{
		Issuer:                          issuer,
		ClientID:                        fapi.ClientID(clientID),
		RedirectURI:                     redirectURI,
		Endpoints:                       discovered.Endpoints,
		Profile:                         profile.clientProfile,
		RequireAuthorizationResponseIss: discovered.AuthorizationResponseIssSupported,
		Algorithms:                      algorithms,
		Limits:                          limits,
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

	session, err := cl.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "begin authorization: "+err.Error())
	}

	finalQuery, err := followAuthorizationRedirect(rawHTTP, session.URL().String())
	if err != nil {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "follow authorization redirect: "+err.Error())
	}

	result, err := cl.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: finalQuery})
	if err != nil {
		return awaitVerdict(rawHTTP, apiBase, module.ID, "complete authorization: "+err.Error())
	}

	switch r := result.(type) {
	case client.CompletionSuccess:
		// The happy-path-shaped module's completion condition is
		// profile-gated (AbstractFAPI2SPFinalClientTest /
		// FAPI2ClientProfileBehavior.userInfoIsResourceEndpoint): for the
		// plain FAPI2 profile this driver targets, calling userinfo alone
		// leaves the module WAITING forever - it specifically wants a GET
		// against the profile's own "accounts" resource endpoint, whose
		// URL isn't part of OIDC discovery at all. The suite instead
		// publishes it as an "exported value" (the same mechanism a human
		// operator reads from the web frontend) under GET
		// /api/runner/{id}, keyed "accounts_endpoint" - confirmed live,
		// not assumed from the Java source alone.
		exposed, err := fetchExposedValues(rawHTTP, apiBase, module.ID)
		if err != nil {
			return "ERROR: fetch exposed values: " + err.Error()
		}
		if accountsEndpoint := exposed["accounts_endpoint"]; accountsEndpoint != "" {
			resourceClient := dpopResourceClient{
				HTTP: rawHTTP, Signer: keyMgr.keys[keys.DPoPProofSigning], Alg: fapi.ES256,
				Random: rand.Reader, Now: time.Now,
			}
			if _, _, err := resourceClient.callProtectedResource(ctx, accountsEndpoint, r.Tokens.AccessToken.Reveal()); err != nil {
				return "ERROR: call accounts endpoint: " + err.Error()
			}
		}
	case client.CompletionDenied:
		// Expected for the modules that deliberately deny the request
		// (e.g. testing that this driver's own consent-rejection handling
		// works) - not logged as an error.
	}
	return awaitVerdict(rawHTTP, apiBase, module.ID, "")
}

// awaitVerdict polls the suite's own graded result for moduleID, which
// is the only thing that actually determines PASS/FAIL — this driver's
// own driverErr (if any) is included for context but never overrides
// it, since for most of this plan's modules a driverErr midway through
// is exactly what the suite wants to see happen.
func awaitVerdict(rawHTTP *http.Client, apiBase, moduleID, driverErr string) string {
	status, result, err := waitUntilFinished(rawHTTP, apiBase, moduleID, 10*time.Second)
	verdict := result
	if err != nil {
		verdict = fmt.Sprintf("status=%s (did not reach a final result: %v)", status, err)
	}
	if driverErr != "" {
		return fmt.Sprintf("%s [driver: %s]", verdict, driverErr)
	}
	return verdict
}

// followAuthorizationRedirect GETs authorizationURL and reads the
// Location header of the 3xx response the suite's mock AS sends back,
// without actually following it — a real RP's own web server would
// handle that hop locally, entirely off the AS's network, so following
// it for real means issuing a GET the suite never expects (confirmed
// live: the suite logs "Got unexpected HTTP call to callback" and
// permanently interrupts the test module if this driver does). Only the
// Location header's query string — code, state, iss — is what
// Client.CompleteAuthorization actually needs.
func followAuthorizationRedirect(baseClient *http.Client, authorizationURL string) (string, error) {
	noRedirectClient := &http.Client{
		Timeout:       baseClient.Timeout,
		Transport:     baseClient.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequest(http.MethodGet, authorizationURL, nil)
	if err != nil {
		return "", err
	}
	res, err := noRedirectClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode < 300 || res.StatusCode >= 400 {
		body, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("authorization endpoint returned %d, want a redirect: %s", res.StatusCode, body)
	}
	location := res.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("redirect response carries no Location header")
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parse Location header: %w", err)
	}
	return redirectURL.RawQuery, nil
}

// randomSuffix returns a short, filesystem/URL-safe random string —
// unique enough to avoid colliding with a previous run's alias, not a
// security-sensitive value.
func randomSuffix() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func containsES256(algs []fapi.SignatureAlgorithm) bool {
	for _, a := range algs {
		if a == fapi.ES256 {
			return true
		}
	}
	return false
}
