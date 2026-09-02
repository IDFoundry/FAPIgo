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
//	go run ./cmd/conformance-client -profile=baseline -mtls
//	go run ./cmd/conformance-client -profile=baseline -client-auth-mtls
//	go run ./cmd/conformance-client -profile=baseline -mtls -client-auth-mtls
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
	"encoding/pem"
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
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
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
	profileName := flag.String("profile", "baseline", "which client test plan to run: baseline, message-signing, or ciba")
	mtls := flag.Bool("mtls", false, "with -profile=ciba or -profile=baseline, present a client certificate and use storage.SenderConstrainMTLS instead of DPoP (RFC 8705 §3) — see mtls.go. Orthogonal to -client-auth-mtls (RFC 8705 §2); combine both for the MTLS+MTLS profile. Ignored/invalid for message-signing.")
	clientAuthMTLS := flag.Bool("client-auth-mtls", false, "with -profile=baseline, register via storage.ClientAuthMethodSelfSignedTLSClientAuth (RFC 8705 §2) instead of private_key_jwt — presents a client certificate instead of a signed client assertion at PAR/token. Orthogonal to -mtls, which is §3 sender-constraining. Ignored/invalid for message-signing/ciba.")
	evidenceDir := flag.String("evidence-dir", "", "if set, write one named log file per test module here in OIDF RP-certification evidence format, alongside the usual combined stdout log — see conformance/client/scripts/README.md's Certification evidence section. Unused by daily CI. Ignored for -profile=ciba.")
	issuer := flag.String("issuer", "", "run a single flow attempt against a FIXED, externally-configured client identity instead of self-generating one and creating a new suite plan — for driving a plan already created through certification.openid.net's own guided web UI (see conformance/client/scripts/README.md and fixed_identity.go). The issuer URL exactly as shown on the suite's own plan page. Requires -client-id, -redirect-uri and -accounts-endpoint; -client-cert/-client-key are required too when -mtls/-client-auth-mtls is set. No suite-graded verdict is available in this mode — check the suite's own plan-detail page for the actual PASS/FAIL result. Not supported with -profile=ciba.")
	clientID := flag.String("client-id", "", "with -issuer: the client_id already registered with the suite for this plan")
	redirectURI := flag.String("redirect-uri", "", "with -issuer: the redirect_uri already registered with the suite for this plan — never actually visited (see followAuthorizationRedirect's own doc comment), but must match exactly for the mock AS's own validation")
	accountsEndpoint := flag.String("accounts-endpoint", "", "with -issuer: the plan's own exported accounts_endpoint value, shown on the suite's plan page — this mode has no suite module ID to fetch it automatically with")
	clientCert := flag.String("client-cert", "", "with -issuer, and -mtls/-client-auth-mtls: PEM file for the client certificate already registered with the suite, instead of generating a throwaway one")
	clientKey := flag.String("client-key", "", "with -issuer, and -mtls/-client-auth-mtls: PEM file for the private key matching -client-cert")
	testName := flag.String("test-name", "", "with -issuer: the module under test, for the evidence file's own TEST: line and log messages only — this mode has no plan/module API call to send it to the suite on")
	scope := flag.String("scope", "openid", "with -issuer: space-delimited scope list to request, exactly matching the plan's own module configuration on the suite (e.g. \"openid offline_access\") — a mismatch here surfaces as a confusing \"authorization response is missing iss\" driver error, not a normal OAuth scope error, since the suite redirects to its own internal log page instead of redirect_uri (see driveAuthorizationFlow's own doc comment)")
	flag.Parse()

	if *issuer != "" {
		if *profileName == "ciba" {
			log.Fatal("conformance-client: -issuer is not supported with -profile=ciba")
		}
		profile, ok := profiles[*profileName]
		if !ok {
			log.Fatalf("conformance-client: unknown -profile %q (want baseline or message-signing)", *profileName)
		}
		cfg := fixedIdentityConfig{
			APIBase: *apiBase, Profile: profile,
			ClientAuthMTLS: *clientAuthMTLS, SenderConstrainMTLS: *mtls,
			EvidenceDir: *evidenceDir,
			Issuer:      *issuer, ClientID: *clientID, RedirectURI: *redirectURI,
			AccountsEndpoint: *accountsEndpoint,
			ClientCertFile:   *clientCert, ClientKeyFile: *clientKey,
			TestName: *testName, Scope: *scope,
		}
		if err := runFixedIdentity(cfg); err != nil {
			log.Fatalf("conformance-client: %v", err)
		}
		return
	}

	if *profileName == "ciba" {
		if *clientAuthMTLS {
			log.Fatal("conformance-client: -client-auth-mtls is not supported with -profile=ciba")
		}
		// CIBA has no browser hop for runModule's shape to drive — see
		// ciba.go's own package doc comment — so it's dispatched
		// separately rather than living in the profiles map below.
		if err := runCIBA(*apiBase, *mtls); err != nil {
			log.Fatalf("conformance-client: %v", err)
		}
		return
	}

	profile, ok := profiles[*profileName]
	if !ok {
		log.Fatalf("conformance-client: unknown -profile %q (want baseline, message-signing, or ciba)", *profileName)
	}
	if *clientAuthMTLS && *profileName != "baseline" {
		log.Fatalf("conformance-client: -client-auth-mtls is only supported with -profile=baseline, got %q", *profileName)
	}
	if *mtls && *profileName != "baseline" {
		log.Fatalf("conformance-client: -mtls is only supported with -profile=ciba or -profile=baseline, got %q", *profileName)
	}

	if err := run(*apiBase, profile, *clientAuthMTLS, *mtls, *evidenceDir); err != nil {
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

func run(apiBase string, profile driverProfile, clientAuthMTLS, senderConstrainMTLS bool, evidenceDir string) error {
	ctx := context.Background()
	rawHTTP := insecureSuiteHTTPClient()

	// Under clientAuthMTLS, no client_assertion is ever built (RFC 8705
	// §2 — the certificate itself is the credential), so this driver
	// needs no ClientAuthentication-purpose key or jwks entry for it at
	// all — mirroring server.jwks.ClientAuthMethod's own conditional
	// PublicJWKS omission on the AS side (client/jwks.go).
	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.DPoPProofSigning: fapi.ES256}
	if !clientAuthMTLS {
		purposes[keys.ClientAuthentication] = fapi.ES256
	}
	if profile.signRequestObject {
		purposes[keys.RequestObjectSigning] = fapi.ES256
	}
	keyMgr, err := ephemeral.NewKeyManager(purposes)
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}

	var jwks []any
	if !clientAuthMTLS {
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
		jwks = append(jwks, clientAuthJWK.WithKeyID(clientAuthPub.KeyID))
	}

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

	suffix := randomSuffix()
	alias := "gofapi-rp-driver-" + suffix
	// clientID varies per run exactly like alias does — see ciba.go's
	// own runCIBA for why a fixed client_id risks cross-run
	// certificate-registration collisions under -mtls; not proven to
	// bite this non-mTLS path the same way, but there's no reason for
	// it to stay fixed here either.
	clientID := "gofapi-rp-driver-client-" + suffix
	redirectURI := apiBase + "test/a/" + alias + "/callback"

	variant := profile.variant
	var clientCertPEM string
	if clientAuthMTLS || senderConstrainMTLS {
		// Copied, not mutated in place: profile.variant is the shared
		// map literal in the profiles table above, reused across runs
		// within the same process (there aren't any today, but nothing
		// stops a future caller from doing so).
		variant = make(map[string]string, len(profile.variant))
		for k, v := range profile.variant {
			variant[k] = v
		}
		if clientAuthMTLS {
			variant["client_auth_type"] = "mtls"
		}
		if senderConstrainMTLS {
			variant["sender_constrain"] = "mtls"
		}

		// One certificate covers both axes when combined — RFC 8705
		// doesn't require separate certificates for §2 client auth vs.
		// §3 sender-constraining, and the suite's own
		// EnsureClientCertificateMatches condition reads the same
		// "client.certificate" plan-config value regardless of which
		// axis triggered the check.
		cert, err := selfSignedClientCert("gofapi-mtls-driver")
		if err != nil {
			return fmt.Errorf("generate client certificate: %w", err)
		}
		rawHTTP = mtlsSuiteHTTPClient(cert)
		// See ciba.go's own runCIBA for why this "client.certificate"
		// plan-config value is required, not optional, under any mTLS
		// client credential — EnsureClientCertificateMatches has no
		// other source for what to compare the presented certificate
		// against.
		clientCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	}

	clientBlock := map[string]any{
		"client_id":    clientID,
		"scope":        "openid",
		"redirect_uri": redirectURI,
	}
	if len(jwks) > 0 {
		clientBlock["jwks"] = map[string]any{"keys": jwks}
	}
	if clientCertPEM != "" {
		clientBlock["certificate"] = clientCertPEM
	}
	planConfig, err := json.Marshal(map[string]any{
		"alias":  alias,
		"client": clientBlock,
	})
	if err != nil {
		return fmt.Errorf("marshal plan config: %w", err)
	}

	planID, moduleNames, err := createPlan(rawHTTP, apiBase, profile.planName, variant, planConfig)
	if err != nil {
		return fmt.Errorf("create plan: %w", err)
	}
	log.Printf("created plan %s (alias %s), %d modules", planID, alias, len(moduleNames))
	log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)

	driver := moduleDriver{
		HTTP: rawHTTP, APIBase: apiBase, PlanID: planID,
		ClientID: clientID, RedirectURI: redirectURI, Keys: keyMgr, Profile: profile,
		ClientAuthMTLS: clientAuthMTLS, SenderConstrainMTLS: senderConstrainMTLS,
	}
	summary := make(map[string]string, len(moduleNames))
	for i, name := range moduleNames {
		log.Printf("--- [%d/%d] %s ---", i+1, len(moduleNames), name)
		result := runModule(ctx, driver, name)
		outcome := result.String()
		summary[name] = outcome
		log.Printf("[%d/%d] %s: %s", i+1, len(moduleNames), name, outcome)
		if evidenceDir != "" {
			if err := writeEvidence(evidenceDir, name, result, apiBase); err != nil {
				log.Printf("[%d/%d] %s: WARNING: write evidence file: %v", i+1, len(moduleNames), name, err)
			}
		}
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
	Keys        *ephemeral.KeyManager
	Profile     driverProfile

	// ClientAuthMTLS selects storage.ClientAuthMethodSelfSignedTLSClientAuth
	// (RFC 8705 §2) instead of the default private_key_jwt — see run's
	// own doc comment on -client-auth-mtls.
	ClientAuthMTLS bool

	// SenderConstrainMTLS selects storage.SenderConstrainMTLS (RFC 8705
	// §3) instead of the default DPoP — see run's own doc comment on
	// -mtls. Orthogonal to ClientAuthMTLS; both may be set together for
	// the MTLS+MTLS profile.
	SenderConstrainMTLS bool
}

// moduleResult is runModule's return value: the suite's own graded
// Verdict (the only thing that actually determines PASS/FAIL) plus
// this driver's own DriverErr, if it hit one, and the suite-assigned
// ModuleID (empty only when createModuleInstance itself failed, before
// the suite ever assigned one). Kept as separate fields rather than one
// pre-formatted string so both run's stdout summary line and
// writeEvidence's per-test evidence file can be built from the same
// data without one parsing the other's output.
type moduleResult struct {
	Verdict   string
	DriverErr string
	ModuleID  string
	// SuiteLogNote overrides evidence.go's default "unavailable —
	// module instance was never created" SUITE LOG line for a result
	// with no ModuleID. That default is only true for a genuine
	// pre-module-creation failure; fixed-identity mode (fixed_identity.go)
	// has no ModuleID for a different reason — it drives a module the
	// suite's own guided UI already created, never queried the API for
	// its ID — and sets this instead so evidence submitted to OIDF
	// doesn't falsely claim the module never existed.
	SuiteLogNote string
	// Interactions is an optional request/response transcript
	// (interactions.go's interactionRecorder.transcript) — writeEvidence
	// appends it as its own section when non-empty, omits it entirely
	// when not (today, only fixed_identity.go ever sets this).
	Interactions string
}

// String reproduces the exact "<verdict> [driver: <err>]" / "<verdict>"
// shape this driver has always printed — generate-report.py's
// parse_rp_log regex-parses the "=== summary ===" block by this exact
// format, so it must stay byte-for-byte stable.
func (r moduleResult) String() string {
	if r.DriverErr != "" {
		return fmt.Sprintf("%s [driver: %s]", r.Verdict, r.DriverErr)
	}
	return r.Verdict
}

// runModule drives testName through the same discover/authorize/token/
// resource sequence every module in this plan needs, and returns a
// moduleResult rather than an error: for most of this plan's modules,
// this driver's own step failing partway through (a rejected ID token,
// a denied callback, ...) is the module's whole point, not a bug in the
// driver, so there is nothing here for a caller to usefully treat as
// fatal. The suite's own graded result — fetched separately, after a
// grace period, back in run — is what actually matters. Module/client
// setup lives in buildModuleClient, split out purely to keep this
// method's own setup/authorize/complete phases readable (go:S3776).
func runModule(ctx context.Context, d moduleDriver, testName string) moduleResult {
	rawHTTP, apiBase, planID := d.HTTP, d.APIBase, d.PlanID
	module, err := createModuleInstance(rawHTTP, apiBase, planID, testName)
	if err != nil {
		return moduleResult{Verdict: "ERROR", DriverErr: "create module instance: " + err.Error()}
	}

	if err := waitUntilWaiting(rawHTTP, apiBase, module.ID, 10*time.Second); err != nil {
		return moduleResult{Verdict: "ERROR", DriverErr: "wait for module ready: " + err.Error(), ModuleID: module.ID}
	}

	cl, failure := buildModuleClient(ctx, d, module)
	if cl == nil {
		return failure
	}

	completion, step, err := driveAuthorizationFlow(ctx, cl, rawHTTP, []string{"openid"})
	if err != nil {
		return awaitVerdict(rawHTTP, apiBase, module.ID, step+": "+err.Error())
	}

	switch r := completion.(type) {
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
		if err := callAccountsEndpoint(ctx, cl, rawHTTP, apiBase, module.ID, r.Tokens); err != nil {
			return moduleResult{Verdict: "ERROR", DriverErr: "call accounts endpoint: " + err.Error(), ModuleID: module.ID}
		}
	case client.CompletionDenied:
		// Expected for the modules that deliberately deny the request
		// (e.g. testing that this driver's own consent-rejection handling
		// works) - not logged as an error.
	}
	return awaitVerdict(rawHTTP, apiBase, module.ID, "")
}

// buildModuleClient discovers module's issuer metadata and constructs
// the client.Client runModule drives through the rest of the flow —
// split out of runModule purely to keep that method's own setup/
// authorize/complete phases readable (go:S3776). A nil *client.Client
// return means module setup itself is this call's whole result: the
// accompanying moduleResult (already run through awaitVerdict where
// appropriate) is what runModule should return unchanged.
func buildModuleClient(ctx context.Context, d moduleDriver, module suiteModule) (*client.Client, moduleResult) {
	rawHTTP, apiBase, clientID, redirectURI, keyMgr, profile := d.HTTP, d.APIBase, d.ClientID, d.RedirectURI, d.Keys, d.Profile

	issuer, err := fapi.ParseIssuerURL(module.URL + "/")
	if err != nil {
		return nil, moduleResult{Verdict: "ERROR", DriverErr: "parse issuer URL: " + err.Error(), ModuleID: module.ID}
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
		return nil, moduleResult{Verdict: "ERROR", DriverErr: "build fetcher: " + err.Error(), ModuleID: module.ID}
	}

	discovered, err := client.Discover(ctx, fetcher, issuer)
	if err != nil {
		return nil, verdictOrDriverErr(rawHTTP, apiBase, module.ID, "discover issuer metadata: "+err.Error())
	}
	if len(discovered.IDTokenAlgorithms) == 0 {
		return nil, verdictOrDriverErr(rawHTTP, apiBase, module.ID, "issuer advertises no recognized ID token signing algorithm")
	}

	issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, discovered.JWKSURI, jwksCacheTTL)
	if err != nil {
		return nil, moduleResult{Verdict: "ERROR", DriverErr: "build issuer key source: " + err.Error(), ModuleID: module.ID}
	}

	algorithms := client.Algorithms{
		DPoP:    fapi.ES256,
		IDToken: discovered.IDTokenAlgorithms[0],
	}
	if !d.ClientAuthMTLS {
		algorithms.ClientAuthentication = fapi.ES256
	}
	limits := client.Limits{
		ClientAssertionLifetime: time.Minute,
		SessionLifetime:         5 * time.Minute,
		MaxIDTokenLifetime:      5 * time.Minute,
		MaxClockSkew:            15 * time.Second,
		HTTPTimeout:             fetchTimeout,
		MaxHTTPResponseBytes:    1 << 20,
		MaxJOSECompactBytes:     16 * 1024,
	}
	if profile.signRequestObject {
		// This driver's key manager only ever generates ES256 keys, so it
		// must specifically pick ES256 out of the issuer's advertised
		// algorithm list rather than blindly take index 0 — the suite
		// lists PS256 first, which this driver has no RSA key to sign
		// with (confirmed live: taking [0] failed every module with
		// "PS256 signer must use an RSA key, got *ecdsa.PublicKey").
		if !containsES256(discovered.RequestObjectAlgorithms) {
			return nil, awaitVerdict(rawHTTP, apiBase, module.ID, "issuer does not advertise ES256 as a request object signing algorithm")
		}
		if len(discovered.JARMAlgorithms) == 0 {
			return nil, awaitVerdict(rawHTTP, apiBase, module.ID, "issuer advertises no recognized JARM signing algorithm")
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
	if d.SenderConstrainMTLS {
		cfg.SenderConstrain = storage.SenderConstrainMTLS
	}
	if d.ClientAuthMTLS {
		cfg.ClientAuthMethod = storage.ClientAuthMethodSelfSignedTLSClientAuth
		// Covers Token+PAR — a superset of what sender-constrain-only
		// needs (Token only; RFC 8705 §3 has no PAR-time
		// pre-commitment concept), so the MTLS+MTLS combo is correctly
		// handled by this branch alone.
		if err := applyMTLSEndpointAliasesForClientAuth(&cfg, discovered); err != nil {
			return nil, awaitVerdict(rawHTTP, apiBase, module.ID, err.Error())
		}
	} else if d.SenderConstrainMTLS {
		if err := applyMTLSEndpointAliases(&cfg, discovered); err != nil {
			return nil, awaitVerdict(rawHTTP, apiBase, module.ID, err.Error())
		}
	}
	deps := client.Dependencies{
		Sessions:   memstore.NewSessionStore(),
		Keys:       keyMgr,
		IssuerKeys: issuerKeys,
		HTTP:       rawHTTP,
		Clock:      client.SystemClock{},
		Random:     rand.Reader,
	}

	cl, err := client.New(cfg, deps)
	if err != nil {
		return nil, moduleResult{Verdict: "ERROR", DriverErr: "construct client: " + err.Error(), ModuleID: module.ID}
	}
	return cl, moduleResult{}
}

// verdictOrDriverErr is buildModuleClient's own choice between polling
// the suite for a real verdict and skipping that entirely: an empty
// moduleID only ever happens in fixed-identity mode (fixed_identity.go),
// which has no suite module ID to poll with in the first place —
// calling awaitVerdict there would hit "api/info/" with nothing after
// it and burn its own full timeout before giving up, for a result it
// was never going to get. runFixedIdentity's own caller already has
// its own "no suite-graded verdict available" messaging for this case.
func verdictOrDriverErr(rawHTTP *http.Client, apiBase, moduleID, driverErr string) moduleResult {
	if moduleID == "" {
		return moduleResult{DriverErr: driverErr}
	}
	return awaitVerdict(rawHTTP, apiBase, moduleID, driverErr)
}

// awaitVerdict polls the suite's own graded result for moduleID, which
// is the only thing that actually determines PASS/FAIL — this driver's
// own driverErr (if any) is included for context but never overrides
// it, since for most of this plan's modules a driverErr midway through
// is exactly what the suite wants to see happen.
//
// The timeout here matters beyond just this one module's own verdict:
// every module in a plan shares one alias (see runCIBA), and this
// driver moves on to create the *next* module instance as soon as this
// call returns — whether or not the suite itself has actually finished
// tearing down the current one. Giving up too early here doesn't just
// misreport this module's own result; it fires the next module's
// createModuleInstance while the suite may still be finalizing the
// current one's alias registration (confirmed live under -mtls,
// where per-module client-certificate registration/cleanup can take
// longer than a short window allows for): the next module then fails
// its own EnsureClientCertificateMatches checks against a
// not-yet-settled registration, gets its alias reclaimed out from
// under it, and every module after that inherits the same fate —
// one slow module cascades into the entire rest of the run reporting
// bogus results, not just its own. 45s comfortably covers the
// suite's own post-completion grace period (AbstractFAPI2SPFinalClientTest's
// waitTimeoutSeconds, default 5s) plus real round-trip latency to an
// external suite instance and this driver's own polling cadence.
func awaitVerdict(rawHTTP *http.Client, apiBase, moduleID, driverErr string) moduleResult {
	status, result, err := waitUntilFinished(rawHTTP, apiBase, moduleID, 45*time.Second)
	verdict := result
	if err != nil {
		verdict = fmt.Sprintf("status=%s (did not reach a final result: %v)", status, err)
	}
	return moduleResult{Verdict: verdict, DriverErr: driverErr, ModuleID: moduleID}
}

// driveAuthorizationFlow drives BeginAuthorization -> follow the
// redirect -> CompleteAuthorization — the middle portion runModule and
// runFixedIdentity (fixed_identity.go) share identically. Each caller
// handles module/client setup before this and the
// CompletionSuccess/CompletionDenied switch after it, since the two
// callers need different accounts-endpoint sources there (runModule's
// own callAccountsEndpoint fetches it via the suite's REST API;
// runFixedIdentity is handed one directly, since it has no suite
// module ID to fetch with). step is a non-empty description of which
// call failed (e.g. "begin authorization"), for callers to build their
// own DriverErr message from — mirrors runModule's pre-refactor
// message shapes exactly, so its own behavior is unchanged. scope is
// the exact space-delimited scope list to request — a self-created
// dev-mode plan always wants "openid" alone, but a hosted plan
// configured through the guided UI can require more (e.g. "openid
// offline_access"), and validates the incoming request against that
// configured value itself. On a mismatch, observed behavior against
// the real hosted suite was not a normal OAuth error redirect back to
// redirect_uri, but a redirect to the suite's own internal log-detail
// page (a bare "log=<id>" query, confirmed via the suite's own log
// viewer) — which this driver then misreports as "authorization
// response is missing iss", since that redirect carries none of the
// expected response parameters at all. Get the scope right and that
// failure mode doesn't come up.
func driveAuthorizationFlow(ctx context.Context, cl *client.Client, rawHTTP *http.Client, scope []string) (completion client.CompletionResult, step string, err error) {
	session, err := cl.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: scope})
	if err != nil {
		return nil, "begin authorization", err
	}

	finalQuery, err := followAuthorizationRedirect(rawHTTP, session.URL().String())
	if err != nil {
		return nil, "follow authorization redirect", err
	}

	completion, err = cl.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: finalQuery})
	if err != nil {
		return nil, "complete authorization", err
	}
	return completion, "", nil
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
