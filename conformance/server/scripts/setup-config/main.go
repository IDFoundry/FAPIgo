// Command setup-config bootstraps everything a fresh clone needs to run
// the AS-side conformance suites (conformance/scripts/run-all.sh's "AS
// baseline" and "AS message-signing" legs) that isn't already committed
// to this repo.
//
// Two files per profile can't be committed at all:
// conformance/server/oidf-config/{baseline,message-signing}-plan.json
// (the OIDF conformance suite's own plan config) are gitignored because
// they carry the test client's *private* JWKS keys — see this repo's
// conformance/server/oidf-config/README.md and .gitignore's own
// comment. This tool generates a fresh ES256 keypair per client per
// profile, writes the private half into the (gitignored) plan config
// alongside everything else that config needs — alias, discovery URL,
// resource block, and the browser/override automation this repo's own
// conformance work has already worked out and documented — and writes
// the matching public half into this repo's own (committed)
// conformance-as config file for that profile, so the two stay in sync.
//
// Idempotent by design: if a profile's plan config already exists, this
// tool leaves that profile alone entirely — it never regenerates keys
// or overwrites a working local setup, it only fills in what's
// missing. Run it again after a `git clean` or on a fresh clone; it's a
// no-op everywhere it already has what it needs.
//
// Usage:
//
//	go run ./conformance/server/scripts/setup-config
//
// Doesn't touch TLS certs (conformance/server/certs/) — run
// conformance/server/scripts/generate-server-cert.sh for those; that
// script is already a one-line, already-idempotent shell script and
// didn't need Go's JSON handling to be made safe to automate.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// profile is everything that differs between the baseline and
// message-signing conformance-suite plans.
type profile struct {
	name       string // matches the *-plan.json / *.config.json filename prefix
	alias      string // suite plan "alias" — also the callback path segment
	issuerHost string // docker-compose service name this profile's AS listens as
	keyLabel1  string // generate-client-key-style label for client 1
	keyLabel2  string // generate-client-key-style label for client 2
}

var profiles = []profile{
	{name: "baseline", alias: "gofapi-baseline", issuerHost: "conformance-as-baseline", keyLabel1: "client1", keyLabel2: "client2"},
	{name: "message-signing", alias: "gofapi-msgsign", issuerHost: "conformance-as-message-signing", keyLabel1: "msgsign-client1", keyLabel2: "msgsign-client2"},
}

func main() {
	dir, err := oidfConfigDir()
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range profiles {
		planPath := filepath.Join(dir, p.name+"-plan.json")
		if _, err := os.Stat(planPath); err == nil {
			fmt.Printf("%s: %s already exists, leaving this profile alone\n", p.name, planPath)
			continue
		}

		priv1, pub1, err := generateKey(p.keyLabel1)
		if err != nil {
			log.Fatalf("%s: generate client1 key: %v", p.name, err)
		}
		priv2, pub2, err := generateKey(p.keyLabel2)
		if err != nil {
			log.Fatalf("%s: generate client2 key: %v", p.name, err)
		}

		configPath := filepath.Join(dir, p.name+".config.json")
		clientIDs, err := patchConformanceASConfig(configPath, pub1, pub2)
		if err != nil {
			log.Fatalf("%s: update %s: %v", p.name, configPath, err)
		}

		if err := writePlanConfig(planPath, p, clientIDs, priv1, priv2); err != nil {
			log.Fatalf("%s: write %s: %v", p.name, planPath, err)
		}
		fmt.Printf("%s: generated fresh client keys, wrote %s and updated %s\n", p.name, planPath, configPath)
	}
}

func oidfConfigDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Works whether invoked as `go run ./conformance/server/scripts/setup-config`
	// from the repo root (the documented usage) or from within this
	// directory directly.
	candidates := []string{
		filepath.Join(wd, "conformance", "server", "oidf-config"),
		filepath.Join(wd, "..", "..", "oidf-config"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("could not locate conformance/server/oidf-config from %s — run this from the repo root", wd)
}

// jwk is the handful of JWK fields this tool's throwaway ES256 keys
// need — see generate-client-key/main.go's own doc comment for why
// this module's internal/jose package isn't used here.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func generateKey(label string) (private, public jwks, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jwks{}, jwks{}, err
	}
	kid := "gofapi-conformance-" + label + "-key1"
	x := b64(priv.X.FillBytes(make([]byte, 32)))
	y := b64(priv.Y.FillBytes(make([]byte, 32)))
	d := b64(priv.D.FillBytes(make([]byte, 32)))

	pub := jwk{Kty: "EC", Crv: "P-256", Alg: "ES256", Use: "sig", Kid: kid, X: x, Y: y}
	priJWK := pub
	priJWK.D = d
	return jwks{Keys: []jwk{priJWK}}, jwks{Keys: []jwk{pub}}, nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// patchConformanceASConfig replaces clients[0].jwks and clients[1].jwks
// in the committed conformance-as config at path with pub1/pub2,
// leaving every other field exactly as it already was — including
// field order, since this rewrites through map[string]json.RawMessage
// rather than a full typed struct, so fields this tool doesn't know
// about survive untouched. Returns the two clients' IDs, needed to
// cross-reference them into the plan config this tool also writes.
func patchConformanceASConfig(path string, pub1, pub2 jwks) (clientIDs [2]string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return clientIDs, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return clientIDs, fmt.Errorf("parse: %w", err)
	}
	var clients []map[string]json.RawMessage
	if err := json.Unmarshal(top["clients"], &clients); err != nil {
		return clientIDs, fmt.Errorf("parse clients: %w", err)
	}
	if len(clients) != 2 {
		return clientIDs, fmt.Errorf("expected exactly 2 clients, found %d", len(clients))
	}

	newJWKS := [2]jwks{pub1, pub2}
	for i := range clients {
		var id string
		if err := json.Unmarshal(clients[i]["id"], &id); err != nil {
			return clientIDs, fmt.Errorf("parse clients[%d].id: %w", i, err)
		}
		clientIDs[i] = id

		encoded, err := json.Marshal(newJWKS[i])
		if err != nil {
			return clientIDs, err
		}
		clients[i]["jwks"] = encoded
	}

	encodedClients, err := json.Marshal(clients)
	if err != nil {
		return clientIDs, err
	}
	top["clients"] = encodedClients

	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return clientIDs, err
	}
	out = append(out, '\n')
	return clientIDs, os.WriteFile(path, out, 0o644)
}

// planConfig mirrors the OIDF conformance suite's own plan config
// shape for this AS's two test plans — see
// conformance/server/oidf-config/README.md for the browser/override
// blocks' own rationale; this struct just gives that same content a
// stable, generatable Go representation.
type planConfig struct {
	Alias  string `json:"alias"`
	Server struct {
		DiscoveryURL string `json:"discoveryUrl"`
	} `json:"server"`
	Client   planClient `json:"client"`
	Client2  planClient `json:"client2"`
	Resource struct {
		ResourceURL string `json:"resourceUrl"`
	} `json:"resource"`
	Browser  []browserBlock           `json:"browser"`
	Override map[string]overrideEntry `json:"override"`
	Options  struct {
		BrowsercontrolCSSEnable bool `json:"browsercontrol_css_enable"`
	} `json:"options"`
}

type planClient struct {
	ClientID       string `json:"client_id"`
	Scope          string `json:"scope"`
	JWKS           jwks   `json:"jwks"`
	DPoPSigningAlg string `json:"dpop_signing_alg"`
}

type browserTask struct {
	Task     string     `json:"task"`
	Match    string     `json:"match"`
	Optional *bool      `json:"optional,omitempty"`
	Commands [][]string `json:"commands"`
}

type browserBlock struct {
	Match      string        `json:"match"`
	MatchLimit *int          `json:"match-limit,omitempty"`
	Tasks      []browserTask `json:"tasks"`
}

type overrideEntry struct {
	Browser []browserBlock `json:"browser"`
}

func writePlanConfig(path string, p profile, clientIDs [2]string, priv1, priv2 jwks) error {
	authorizeURL := "https://" + p.issuerHost + ":8443/authorize*"
	trueVal := true
	one := 1

	consentTask := browserTask{
		Task: "Consent", Match: authorizeURL, Optional: &trueVal,
		Commands: [][]string{{"click", "xpath", "//button[@name='decision' and @value='approve']", "optional"}},
	}
	consentBlock := browserBlock{Match: authorizeURL, Tasks: []browserTask{consentTask}}

	cfg := planConfig{Alias: p.alias}
	cfg.Server.DiscoveryURL = "https://" + p.issuerHost + ":8443/.well-known/openid-configuration"
	cfg.Client = planClient{ClientID: clientIDs[0], Scope: "openid accounts offline_access", JWKS: priv1, DPoPSigningAlg: "ES256"}
	cfg.Client2 = planClient{ClientID: clientIDs[1], Scope: "openid accounts offline_access", JWKS: priv2, DPoPSigningAlg: "ES256"}
	cfg.Resource.ResourceURL = "https://" + p.issuerHost + ":8443/accounts"
	cfg.Browser = []browserBlock{consentBlock}
	cfg.Override = map[string]overrideEntry{
		"fapi2-security-profile-final-user-rejects-authentication": {
			Browser: []browserBlock{{
				Match: authorizeURL,
				Tasks: []browserTask{{
					Task: "Deny", Match: authorizeURL,
					Commands: [][]string{{"click", "xpath", "//button[@name='decision' and @value='deny']", "optional"}},
				}},
			}},
		},
		"fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": {
			Browser: []browserBlock{
				{Match: authorizeURL, MatchLimit: &one, Tasks: []browserTask{}},
				consentBlock,
			},
		},
	}
	cfg.Options.BrowsercontrolCSSEnable = false

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}
