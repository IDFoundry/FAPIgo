// This file adds a second run mode for driving the OIDF hosted
// certification.openid.net suite, alongside main.go's own run(): unlike
// local dev-mode, the hosted suite requires a plan to be created
// through its own guided web UI first, with a fixed alias/client_id/
// certificate registered up front — confirmed both against the live
// hosted UI (which shows "Exported Values" — issuer, discoveryUrl,
// accounts_endpoint — all scoped to that fixed alias and identical
// across every module in the plan) and against OIDF's own official
// reference RP client (gitlab.com/openid/sample-openbanking-client-nodejs),
// which takes ISSUER/ACCOUNTS as direct, literal config rather than
// fetching them dynamically, uses fixed pre-registered certificate/key
// files rather than generating one per run, and drives one flow
// attempt per invocation with no plan creation and no polling — see
// conformance/client/scripts/README.md.
//
// run()'s own self-generating, plan-creating mode stays the default
// and is unchanged; -issuer's presence is the sole switch to this mode.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// fixedIdentityConfig is runFixedIdentity's input — every value a
// hosted plan pins in advance through its own guided web UI. See this
// file's own package-level doc comment for why this mode exists.
type fixedIdentityConfig struct {
	APIBase             string
	Profile             driverProfile
	ClientAuthMTLS      bool
	SenderConstrainMTLS bool
	EvidenceDir         string

	Issuer           string
	ClientID         string
	RedirectURI      string
	AccountsEndpoint string
	ClientCertFile   string
	ClientKeyFile    string
	TestName         string
	// Scope is the space-delimited scope list to request — must match
	// the plan's own module configuration on the suite exactly (see
	// driveAuthorizationFlow's own doc comment in main.go for why a
	// mismatch here can produce confusing, unrelated-looking failures
	// rather than a clean insufficient-scope error). Empty defaults to
	// "openid" in runFixedIdentity.
	Scope string
}

// validate reports every missing companion flag at once, rather than
// failing deep inside client construction on whichever one happens to
// be read first — -issuer alone gives no useful error location once
// that's underway.
func (c fixedIdentityConfig) validate() error {
	var missing []string
	if c.ClientID == "" {
		missing = append(missing, "-client-id")
	}
	if c.RedirectURI == "" {
		missing = append(missing, "-redirect-uri")
	}
	if c.AccountsEndpoint == "" {
		missing = append(missing, "-accounts-endpoint")
	}
	if c.ClientAuthMTLS || c.SenderConstrainMTLS {
		if c.ClientCertFile == "" {
			missing = append(missing, "-client-cert")
		}
		if c.ClientKeyFile == "" {
			missing = append(missing, "-client-key")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("-issuer requires %s to also be set", strings.Join(missing, ", "))
	}
	return nil
}

// runFixedIdentity drives a single flow attempt against c's fixed
// client identity instead of self-generating one and creating a new
// suite plan — see this file's own package doc comment. There is no
// suite-graded verdict to report: the suite's own plan-detail page is
// the source of truth for PASS/FAIL, same as it always has been for
// certification submission (conformance/client/scripts/README.md's own
// "Certification evidence" section) — this driver's evidence has only
// ever been supplementary evidence of what the client itself did.
func runFixedIdentity(c fixedIdentityConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	ctx := context.Background()
	rawHTTP := insecureSuiteHTTPClient()

	// Mirrors run()'s own key-purpose selection (main.go) exactly —
	// under ClientAuthMTLS, no client_assertion is ever built (RFC 8705
	// §2 — the certificate itself is the credential), so no
	// ClientAuthentication-purpose key is needed.
	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.DPoPProofSigning: fapi.ES256}
	if !c.ClientAuthMTLS {
		purposes[keys.ClientAuthentication] = fapi.ES256
	}
	if c.Profile.signRequestObject {
		purposes[keys.RequestObjectSigning] = fapi.ES256
	}
	keyMgr, err := ephemeral.NewKeyManager(purposes)
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}

	if c.ClientAuthMTLS || c.SenderConstrainMTLS {
		cert, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile)
		if err != nil {
			return fmt.Errorf("load client certificate: %w", err)
		}
		rawHTTP = mtlsSuiteHTTPClient(cert)
	}

	issuerURL, err := fapi.ParseIssuerURL(c.Issuer)
	if err != nil {
		return fmt.Errorf("parse -issuer: %w", err)
	}
	// buildModuleClient (main.go) derives its own issuer from
	// module.URL+"/" — strip any trailing slash from the given -issuer
	// first so the round trip lands back on exactly what was supplied,
	// matching a real suiteModule.URL's own shape (suite.go's
	// createModuleInstance never returns one with a trailing slash
	// either).
	module := suiteModule{ID: "", URL: strings.TrimSuffix(issuerURL.String(), "/")}

	driver := moduleDriver{
		HTTP: rawHTTP, APIBase: c.APIBase,
		ClientID: c.ClientID, RedirectURI: c.RedirectURI, Keys: keyMgr, Profile: c.Profile,
		ClientAuthMTLS: c.ClientAuthMTLS, SenderConstrainMTLS: c.SenderConstrainMTLS,
	}

	// cl == nil means buildModuleClient rejected the issuer before
	// authorization ever began (e.g. a discovery-time check like the
	// issuer-mismatch anti-spoofing check, OIDC Discovery 1.0 §4.3).
	// For a negative-test module that's the correct, desired client
	// behavior — not a driver crash — so this is reported and
	// evidenced exactly like a driver error later in the flow, never
	// as a fatal error with no evidence left behind.
	outcome, driverErr := "completed successfully", ""
	cl, failure := buildModuleClient(ctx, driver, module)
	switch {
	case cl == nil:
		driverErr = failure.DriverErr
		outcome = "client rejected the issuer before authorization began"
	default:
		scope := strings.Fields(c.Scope)
		if len(scope) == 0 {
			scope = []string{"openid"}
		}
		completion, step, err := driveAuthorizationFlow(ctx, cl, rawHTTP, scope)
		switch {
		case err != nil:
			driverErr = step + ": " + err.Error()
			outcome = "driver error"
		default:
			switch r := completion.(type) {
			case client.CompletionSuccess:
				if err := callAccountsEndpointDirect(ctx, cl, c.AccountsEndpoint, r.Tokens); err != nil {
					driverErr = "call accounts endpoint: " + err.Error()
					outcome = "driver error"
				}
			case client.CompletionDenied:
				outcome = "authorization denied"
			}
		}
	}

	log.Printf("fixed-identity run (%s): %s", c.TestName, outcome)
	if driverErr != "" {
		log.Printf("driver error: %s", driverErr)
	}
	log.Printf("no suite-graded verdict is available in fixed-identity mode — check the suite's own plan-detail page for the actual PASS/FAIL result")

	if c.EvidenceDir != "" {
		result := moduleResult{
			Verdict:   "unavailable in fixed-identity mode — see the suite's own plan-detail page",
			DriverErr: driverErr,
			SuiteLogNote: "not queried via API in fixed-identity mode (no known module ID) — the module instance " +
				"does exist (it was created through the suite's own guided web UI, not by this driver); find its " +
				"log-detail.html link on the suite's plan-detail page for -issuer=" + c.Issuer,
		}
		if err := writeEvidence(c.EvidenceDir, c.TestName, result, c.APIBase); err != nil {
			log.Printf("WARNING: write evidence file: %v", err)
		}
	}
	return nil
}
