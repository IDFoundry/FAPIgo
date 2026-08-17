// Command conformance-client drives this module's client package
// through every module of the FAPI2 baseline (non-message-signing)
// relying-party conformance test plan against a locally running OIDF
// conformance suite, entirely headlessly: it plays both the RP under
// test (via the client package) and the "browser" that carries requests
// between the RP and the suite's mock authorization server, since
// neither role here needs a human or a real browser — the suite's mock
// AS doesn't render an interactive consent page for a
// private_key_jwt+DPoP RP test, and this driver's own HTTP client can
// intercept the authorization redirect itself.
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
//	go run ./cmd/conformance-client
//
// With no flags it talks to the suite's default local dev-mode address,
// https://localhost.emobix.co.uk:8443/ — the same instance
// conformance/server's own scripts target.
package main

import (
	"context"
	"crypto/ecdsa"
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

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/client"
	"github.com/osanderson/go-fapi/fapihttp"
	"github.com/osanderson/go-fapi/keys"
)

const (
	planName     = "fapi2-security-profile-final-client-test-plan"
	testName     = "fapi2-security-profile-final-client-test-happy-path"
	fetchTimeout = 15 * time.Second
	jwksCacheTTL = time.Minute
)

func main() {
	apiBase := flag.String("suite", "https://localhost.emobix.co.uk:8443/", "conformance suite base URL")
	flag.Parse()

	if err := run(*apiBase); err != nil {
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

func run(apiBase string) error {
	ctx := context.Background()
	rawHTTP := insecureSuiteHTTPClient()

	keyMgr, err := newEphemeralKeyManager([]keys.SigningPurpose{keys.ClientAuthentication, keys.DPoPProofSigning})
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}
	pub, err := keyMgr.PublicKey(ctx, keys.ClientAuthentication, fapi.ES256)
	if err != nil {
		return fmt.Errorf("read client authentication public key: %w", err)
	}
	pubECDSA, ok := pub.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("client authentication public key is not ECDSA")
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
				"keys": []any{jwkFromECDSAPublicKey(pubECDSA, pub.KeyID)},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal plan config: %w", err)
	}

	variant := map[string]string{
		"client_auth_type": "private_key_jwt",
		"sender_constrain": "dpop",
		"fapi_profile":     "plain_fapi",
		"fapi_client_type": "oidc",
	}
	planID, moduleNames, err := createPlan(rawHTTP, apiBase, planName, variant, planConfig)
	if err != nil {
		return fmt.Errorf("create plan: %w", err)
	}
	log.Printf("created plan %s (alias %s), %d modules", planID, alias, len(moduleNames))
	log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)

	summary := make(map[string]string, len(moduleNames))
	for i, name := range moduleNames {
		log.Printf("--- [%d/%d] %s ---", i+1, len(moduleNames), name)
		outcome := runModule(ctx, rawHTTP, apiBase, planID, name, clientID, redirectURI, keyMgr)
		summary[name] = outcome
		log.Printf("[%d/%d] %s: %s", i+1, len(moduleNames), name, outcome)
	}

	log.Printf("=== summary ===")
	for _, name := range moduleNames {
		log.Printf("%-16s %s", summary[name], name)
	}
	return nil
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
func runModule(ctx context.Context, rawHTTP *http.Client, apiBase, planID, testName, clientID, redirectURI string, keyMgr *ephemeralKeyManager) string {
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

	cfg := client.Config{
		Issuer:                          issuer,
		ClientID:                        fapi.ClientID(clientID),
		RedirectURI:                     redirectURI,
		Endpoints:                       discovered.Endpoints,
		Profile:                         client.ProfileFAPISecurity,
		RequireAuthorizationResponseIss: discovered.AuthorizationResponseIssSupported,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256,
			DPoP:                 fapi.ES256,
			IDToken:              discovered.IDTokenAlgorithms[0],
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute,
			SessionLifetime:         5 * time.Minute,
			MaxIDTokenLifetime:      5 * time.Minute,
			MaxClockSkew:            15 * time.Second,
			HTTPTimeout:             fetchTimeout,
			MaxHTTPResponseBytes:    1 << 20,
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
			if _, _, err := callProtectedResource(ctx, rawHTTP, keyMgr.keys[keys.DPoPProofSigning], fapi.ES256,
				rand.Reader, time.Now, accountsEndpoint, r.Tokens.AccessToken.Reveal()); err != nil {
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
	defer res.Body.Close()

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

func jwkFromECDSAPublicKey(pub *ecdsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
		"x": base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
	}
}
