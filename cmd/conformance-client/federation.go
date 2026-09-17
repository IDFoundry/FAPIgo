// This file adds -profile=federation: the OpenID Federation 1.0 "RP
// joined to test federation" conformance plan
// (openid-federation-entity-joined-to-test-federation-rp-test-plan) —
// the suite plays the OP, self-hosting its own Trust Anchor exactly as
// it does for the OP-side plan cmd/conformance-as's own
// -federation-trust-anchor-admin work drives (same alias-based
// predictable-Entity-Identifier trick, for the same race-avoidance
// reason — see that work's own commit history), but every relationship
// here runs the opposite direction: instead of the suite resolving a
// client through federation, *this* driver resolves the suite's own
// self-hosted OP through federation (client.DiscoverViaFederation) and
// authenticates to it using an Entity Configuration this driver signs
// and serves itself — federation_server.go's own live listener, since
// unlike the OP-side scenario there's no way to hand the suite a
// pre-built static document up front that covers every fetch the suite
// ends up making (see that file's own doc comment for the one this
// driver found the hard way, by reading the suite's own source rather
// than assuming from its "server_metadata" variant name).
//
// Every piece of cryptographic material both sides need is generated
// by *this* driver, never the suite: this driver's own federation
// signing key and client-authentication key (both ES256, matching
// every other profile in this package), plus three more the suite
// itself signs with, handed over as private JWK Sets in the plan
// config — federation.op_ec_jwks (the suite's own Entity Configuration
// signing key, playing the OP), federation.op_server_jwks (the suite's
// own OIDC operational signing key, e.g. for the ID token), and
// federation_trust_anchor.trust_anchor_jwks (the suite's self-hosted
// Trust Anchor's own signing key) — confirmed against
// OpenIDFederationClientTest.java's own configure() method, which reads
// all three from config rather than generating any of them itself.
// This driver already has the Trust Anchor's own public half locally
// once it generates that key, so unlike every discovery this package
// otherwise does, DiscoverViaFederation's own trust anchor is pinned
// from a value this driver made up itself, not fetched or configured
// externally.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const federationPlanName = "openid-federation-entity-joined-to-test-federation-rp-test-plan"

// openIDRelyingPartyMetadata is this driver's own "openid_relying_party"
// federation metadata (OpenID Federation 1.0 §5.2), signed into its own
// Entity Configuration below — deliberately sets token_endpoint_auth_method
// explicitly: AddOpenIDRelyingPartyMetadataToEntityConfiguration.java
// (the suite's own, structurally identical builder for its self-hosted
// RP in the OP-side plan) never sets this field at all, which is the
// exact gap PR #320 traced FAPIgo's own PAR endpoint's correct
// rejection of an auto-registered client with no declared auth method
// back to — this driver has no reason to repeat that omission on its
// own metadata just because the suite's own does.
type openIDRelyingPartyMetadata struct {
	ClientRegistrationTypes []string       `json:"client_registration_types"`
	ResponseTypes           []string       `json:"response_types"`
	RedirectURIs            []string       `json:"redirect_uris"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method"`
	JWKS                    map[string]any `json:"jwks"`
}

// runFederationRP drives every module of the federation RP test plan
// against apiBase, following the exact same create-plan / loop-over-
// modules / print-summary shape run (main.go) uses for every other
// plan — only module setup (buildFederationModuleClient, below) and
// this plan's own config differ enough to need their own file.
func runFederationRP(apiBase, evidenceDir string) error {
	ctx := context.Background()
	rawHTTP := insecureSuiteHTTPClient()

	listener, port, err := newFederationRPListener()
	if err != nil {
		return fmt.Errorf("start federation listener: %w", err)
	}
	entityID := fmt.Sprintf("https://%s:%d", federationRPListenHost, port)
	redirectURI := entityID + "/callback"

	alias := "gofapi-fed-rp-" + randomSuffix()
	// Same predictable-Entity-Identifier trick as
	// cmd/conformance-as/federation_trust_anchor_admin.go's own
	// orchestration needed on the OP side, and for the identical
	// reason: this driver's own Entity Configuration must name the
	// suite's self-hosted Trust Anchor in its authority_hints *before*
	// the plan (let alone the Trust Anchor itself) exists, and the
	// suite's own module base URL is otherwise only known — as a
	// random path segment — after module creation, too late to be
	// signed into anything.
	trustAnchorEntityID := apiBase + "test/a/" + alias + "/trust-anchor"

	rpFederationPriv, rpFederationPrivJWKS, err := generateFederationJWK("rp-fed-key1")
	if err != nil {
		return fmt.Errorf("generate rp federation key: %w", err)
	}
	rpClientAuthPriv, _, err := generateFederationJWK("rp-client-key1")
	if err != nil {
		return fmt.Errorf("generate rp client authentication key: %w", err)
	}
	rpClientAuthPub, err := jose.NewJWK(&rpClientAuthPriv.PublicKey, fapi.ES256)
	if err != nil {
		return fmt.Errorf("build rp client authentication public jwk: %w", err)
	}
	rpClientAuthPubBytes, err := rpClientAuthPub.WithKeyID("rp-client-key1").MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal rp client authentication public jwk: %w", err)
	}
	var rpClientAuthPubJSON map[string]any
	if err := json.Unmarshal(rpClientAuthPubBytes, &rpClientAuthPubJSON); err != nil {
		return fmt.Errorf("decode rp client authentication public jwk: %w", err)
	}

	_, opECJWKS, err := generateFederationJWK("op-ec-key1")
	if err != nil {
		return fmt.Errorf("generate op entity configuration key: %w", err)
	}
	_, opServerJWKS, err := generateFederationJWK("op-server-key1")
	if err != nil {
		return fmt.Errorf("generate op server key: %w", err)
	}
	_, trustAnchorJWKS, err := generateFederationJWK("ta-key1")
	if err != nil {
		return fmt.Errorf("generate trust anchor key: %w", err)
	}
	trustAnchorPubJWKS, err := json.Marshal(publicJWKS(trustAnchorJWKS))
	if err != nil {
		return fmt.Errorf("marshal trust anchor public jwks: %w", err)
	}

	rpMetadataJSON, err := json.Marshal(openIDRelyingPartyMetadata{
		ClientRegistrationTypes: []string{"automatic"},
		ResponseTypes:           []string{"code"},
		RedirectURIs:            []string{redirectURI},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    map[string]any{"keys": []any{rpClientAuthPubJSON}},
	})
	if err != nil {
		return fmt.Errorf("marshal rp metadata: %w", err)
	}

	rpFederationPubJWKSBytes, err := json.Marshal(publicJWKS(rpFederationPrivJWKS))
	if err != nil {
		return fmt.Errorf("marshal rp federation public jwks: %w", err)
	}
	issuer, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID:       entityID,
		AuthorityHints: []string{trustAnchorEntityID},
		Lifetime:       24 * time.Hour,
	}, federation.SelfIssueDependencies{
		Signer: rpFederationPriv, Algorithm: fapi.ES256, KeyID: "rp-fed-key1",
		JWKS: rpFederationPubJWKSBytes, Clock: federation.SystemClock{},
	})
	if err != nil {
		return fmt.Errorf("build self issuer: %w", err)
	}
	entityConfigurationJWT, err := issuer.EntityConfiguration(map[string]json.RawMessage{
		"openid_relying_party": rpMetadataJSON,
	})
	if err != nil {
		return fmt.Errorf("sign entity configuration: %w", err)
	}

	srv := serveFederationRPServer(listener, entityConfigurationJWT)
	defer func() { _ = srv.Close() }()
	log.Printf("federation RP entity configuration served at %s%s", entityID, federation.WellKnownPath)

	planConfig, err := json.Marshal(map[string]any{
		"alias": alias,
		"federation": map[string]any{
			"entity_identifier": entityID,
			"trust_anchor":      trustAnchorEntityID,
			"op_ec_jwks":        opECJWKS,
			"op_server_jwks":    opServerJWKS,
		},
		"federation_trust_anchor": map[string]any{"trust_anchor_jwks": trustAnchorJWKS},
	})
	if err != nil {
		return fmt.Errorf("marshal plan config: %w", err)
	}
	variant := map[string]string{"client_registration": "automatic", "server_metadata": "discovery"}

	planID, moduleNames, err := createPlan(rawHTTP, apiBase, federationPlanName, variant, planConfig)
	if err != nil {
		return fmt.Errorf("create plan: %w", err)
	}
	log.Printf("created plan %s (alias %s), %d modules", planID, alias, len(moduleNames))
	log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)

	fetcher, err := fapihttp.New(rawHTTP, fapihttp.Config{
		MaxResponseBytes: 1 << 20,
		RequestTimeout:   fetchTimeout,
		MaxRedirects:     5,
		// Both directions this driver talks to under this profile
		// resolve to loopback: apiBase (the suite) and, once
		// federationRPListenHost's own DNS resolves back here on this
		// host, this driver's own live endpoint too.
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		return fmt.Errorf("build fetcher: %w", err)
	}
	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: trustAnchorEntityID, JWKS: trustAnchorPubJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxStatementLifetime: 25 * time.Hour, MaxClockSkew: 30 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: federation.SystemClock{}})
	if err != nil {
		return fmt.Errorf("build resolver: %w", err)
	}

	dpopSigner, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return fmt.Errorf("generate dpop key: %w", err)
	}
	keyMgr, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{
			keys.ClientAuthentication: rpClientAuthPriv,
			keys.DPoPProofSigning:     dpopSigner,
		},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{
			keys.ClientAuthentication: fapi.ES256,
			keys.DPoPProofSigning:     fapi.ES256,
		},
		map[keys.SigningPurpose]string{keys.ClientAuthentication: "rp-client-key1"},
	)
	if err != nil {
		return fmt.Errorf("build key manager: %w", err)
	}

	driver := federationModuleDriver{
		HTTP: rawHTTP, APIBase: apiBase, PlanID: planID,
		EntityID: entityID, RedirectURI: redirectURI,
		Resolver: resolver, Keys: keyMgr, Fetcher: fetcher,
	}
	summary := make(map[string]string, len(moduleNames))
	for i, name := range moduleNames {
		log.Printf("--- [%d/%d] %s ---", i+1, len(moduleNames), name)
		result := runFederationModule(ctx, driver, name)
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

// federationModuleDriver holds everything runFederationModule needs
// that stays fixed across every module in the plan — the federation
// counterpart of moduleDriver (main.go).
type federationModuleDriver struct {
	HTTP        *http.Client
	APIBase     string
	PlanID      string
	EntityID    string
	RedirectURI string
	Resolver    *federation.Resolver
	Keys        keys.KeyManager
	Fetcher     *fapihttp.Client
}

// runFederationModule mirrors runModule (main.go): create the module
// instance, wait for it to reach WAITING, build a client.Client and
// drive it through BeginAuthorization/CompleteAuthorization
// (driveAuthorizationFlow, main.go — identical for every profile), then
// await the suite's own graded verdict. Two differences from runModule
// itself: buildFederationModuleClient (below) discovers the suite's own
// self-hosted OP via DiscoverViaFederation instead of plain TLS
// Discover, and there is no callAccountsEndpoint step —
// OpenIDFederationClientTest.java's own tokenResponse() (unlike
// AbstractFAPI2SPFinalClientTest's modules) calls fireTestFinished() the
// moment it issues an ID token, so this plan never expects a call to
// any further resource endpoint.
func runFederationModule(ctx context.Context, d federationModuleDriver, testName string) moduleResult {
	rawHTTP, apiBase, planID := d.HTTP, d.APIBase, d.PlanID
	module, err := createModuleInstance(rawHTTP, apiBase, planID, testName)
	if err != nil {
		return moduleResult{Verdict: "ERROR", DriverErr: "create module instance: " + err.Error()}
	}

	if err := waitUntilWaiting(rawHTTP, apiBase, module.ID, 10*time.Second); err != nil {
		return moduleResult{Verdict: "ERROR", DriverErr: "wait for module ready: " + err.Error(), ModuleID: module.ID}
	}

	cl, failure := buildFederationModuleClient(ctx, d, module)
	if cl == nil {
		return failure
	}

	_, _, err = driveAuthorizationFlow(ctx, cl, rawHTTP, []string{"openid"})
	if err != nil {
		return awaitVerdict(rawHTTP, apiBase, module.ID, err.Error())
	}
	return awaitVerdict(rawHTTP, apiBase, module.ID, "")
}

// buildFederationModuleClient discovers module's issuer metadata via
// OpenID Federation (client.DiscoverViaFederation, d.Resolver already
// pinned to the suite's self-hosted Trust Anchor) rather than plain TLS
// Discover, and constructs the client.Client runFederationModule drives
// through the rest of the flow — the federation counterpart of
// buildModuleClient (main.go).
func buildFederationModuleClient(ctx context.Context, d federationModuleDriver, module suiteModule) (*client.Client, moduleResult) {
	// No trailing slash: the suite's own self-hosted OP declares its
	// Entity Configuration's iss/sub claims as module.URL verbatim
	// (confirmed live — appending "/" here, matching main.go's own
	// fapi.ParseIssuerURL(module.URL+"/") convention for plain OIDC
	// discovery, made every module fail with an iss/sub mismatch
	// against "the requested entity ID").
	issuerID := module.URL
	issuer, err := fapi.ParseIssuerURL(issuerID)
	if err != nil {
		return nil, moduleResult{Verdict: "ERROR", DriverErr: "parse issuer URL: " + err.Error(), ModuleID: module.ID}
	}

	discovered, err := client.DiscoverViaFederation(ctx, d.Resolver, issuerID)
	if err != nil {
		return nil, verdictOrDriverErr(d.HTTP, d.APIBase, module.ID, "discover issuer via federation: "+err.Error())
	}
	if len(discovered.IDTokenAlgorithms) == 0 {
		return nil, verdictOrDriverErr(d.HTTP, d.APIBase, module.ID, "issuer advertises no recognized ID token signing algorithm")
	}

	issuerKeys, err := keys.NewJWKSIssuerKeySource(d.Fetcher, discovered.JWKSURI, jwksCacheTTL)
	if err != nil {
		return nil, moduleResult{Verdict: "ERROR", DriverErr: "build issuer key source: " + err.Error(), ModuleID: module.ID}
	}

	cfg := client.Config{
		Issuer:      issuer,
		ClientID:    fapi.ClientID(d.EntityID),
		RedirectURI: d.RedirectURI,
		Endpoints:   discovered.Endpoints,
		Profile:     client.ProfileFAPISecurity,
		Assurance:   client.AssuranceDevelopment,
		Algorithms: client.Algorithms{
			DPoP:                 fapi.ES256,
			IDToken:              discovered.IDTokenAlgorithms[0],
			ClientAuthentication: fapi.ES256,
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute,
			SessionLifetime:         5 * time.Minute,
			MaxIDTokenLifetime:      5 * time.Minute,
			MaxClockSkew:            15 * time.Second,
			HTTPTimeout:             fetchTimeout,
			MaxHTTPResponseBytes:    1 << 20,
			MaxJOSECompactBytes:     16 * 1024,
		},
	}
	deps := client.Dependencies{
		Sessions:   memstore.NewSessionStore(),
		Keys:       d.Keys,
		IssuerKeys: issuerKeys,
		HTTP:       d.HTTP,
		Clock:      client.SystemClock{},
		Random:     rand.Reader,
	}

	cl, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		return nil, moduleResult{Verdict: "ERROR", DriverErr: "construct client: " + err.Error(), ModuleID: module.ID}
	}
	return cl, moduleResult{}
}
