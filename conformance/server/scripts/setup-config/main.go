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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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
		privRS256, pubRS256, err := generatePS256Key("gofapi-conformance-" + p.keyLabel1 + "-rs256-key1")
		if err != nil {
			log.Fatalf("%s: generate RS256 test-client key: %v", p.name, err)
		}

		configPath := filepath.Join(dir, p.name+".config.json")
		clientIDs, rs256ClientID, err := patchConformanceASConfig(configPath, p, pub1, pub2, pubRS256)
		if err != nil {
			log.Fatalf("%s: update %s: %v", p.name, configPath, err)
		}

		if err := writePlanConfig(planPath, p, clientIDs, rs256ClientID, priv1, priv2, privRS256); err != nil {
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

// jwk is the handful of JWK fields this tool's throwaway keys need —
// see generate-client-key/main.go's own doc comment for why this
// module's internal/jose package isn't used here. Covers both the
// EC keys every client normally signs with (kty/crv/x/y/d) and the
// one-off RSA/PS256 key used only for the two RS256-must-be-rejected
// negative tests (kty/n/e/d/p/q/dp/dq/qi) — omitempty on both sets so
// a given key only ever prints the fields its own key type actually
// has.
type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	D   string `json:"d,omitempty"`

	// EC (P-256 / ES256)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// RSA (PS256)
	N  string `json:"n,omitempty"`
	E  string `json:"e,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	DP string `json:"dp,omitempty"`
	DQ string `json:"dq,omitempty"`
	QI string `json:"qi,omitempty"`
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

// generatePS256Key produces a fresh 2048-bit RSA keypair, alg PS256,
// as a single-key private/public JWKS pair — used for the dedicated
// third client (see patchConformanceASConfig) that
// ensure-signed-{client-assertion,request-object}-with-RS256-fails
// need to actually run rather than SKIP.
//
// Both modules gate their own SKIPPED result on
// client_jwks.keys[0].alg == "PS256" exactly (JWKUtil.getAlgFromClientJwks
// in the conformance-suite source) — FAPI permits ES256 *or* PS256, so
// this is the "normal" algorithm the module expects its base key to
// already declare, and each module's own logic then mutates only a
// narrow, specific signing operation (the token-endpoint client
// assertion for the first module; the request object for the second)
// to RS256 in place, leaving everything else — including PAR's own
// client assertion — signed normally with this same PS256 key, to
// confirm only the deliberately-wrong operation gets rejected.
//
// This is why a dedicated client is unavoidable, not just a plan
// -config key swap: FAPIgo's server.AlgorithmPolicy requires a
// client's *registered* algorithm to be in the server's own globally
// -permitted set (server/par.go's Algorithms.ClientAssertion.Contains
// / Algorithms.RequestObject.Contains checks) before anything else is
// even attempted, and storage.RegisteredClient pins exactly one
// algorithm per client — so a client already registered for ES256
// cannot simply present a PS256-signed assertion for its *normal*
// requests and expect them to succeed. client1/client2 stay ES256
// -only exactly as every other test in the plan needs; this third
// client is registered for PS256 only, existing solely so these two
// negative tests have a legitimately-configured starting point to
// deviate from.
func generatePS256Key(kid string) (private, public jwks, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return jwks{}, jwks{}, err
	}
	priv.Precompute()

	pub := jwk{
		Kty: "RSA", Alg: "PS256", Use: "sig", Kid: kid,
		N: b64(priv.N.Bytes()), E: b64(big.NewInt(int64(priv.E)).Bytes()),
	}
	priJWK := pub
	priJWK.D = b64(priv.D.Bytes())
	priJWK.P = b64(priv.Primes[0].Bytes())
	priJWK.Q = b64(priv.Primes[1].Bytes())
	priJWK.DP = b64(priv.Precomputed.Dp.Bytes())
	priJWK.DQ = b64(priv.Precomputed.Dq.Bytes())
	priJWK.QI = b64(priv.Precomputed.Qinv.Bytes())
	return jwks{Keys: []jwk{priJWK}}, jwks{Keys: []jwk{pub}}, nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// marshalIndentNoEscape is json.MarshalIndent, except it doesn't
// HTML-escape '&', '<', '>' — json.Marshal's default behavior turns a
// redirect_uri's plain "&" into "&", which is valid JSON but
// needlessly unreadable in a file meant to be hand-edited too.
func marshalIndentNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder.Encode always appends its own trailing newline;
	// callers here append their own, so trim it back off first.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// patchConformanceASConfig replaces clients[0].jwks and clients[1].jwks
// in the committed conformance-as config at path with pub1/pub2,
// leaving every other field exactly as it already was — including
// field order, since this rewrites through map[string]json.RawMessage
// rather than a full typed struct, so fields this tool doesn't know
// about survive untouched. Returns the two clients' IDs, needed to
// cross-reference them into the plan config this tool also writes.
//
// Also ensures a third, PS256-registered client exists — appending
// one if the config doesn't have it yet, or just refreshing its jwks
// if it does (idempotent re-runs, e.g. after client.jwks.keys[0]
// already exists but *-plan.json was deleted) — and that "PS256" is
// present in the server's own globally-permitted algorithm sets
// (algorithms.client_assertion always; algorithms.request_object only
// for the message-signing profile, which is the only one that ever
// sends a signed request object at all). See generatePS256Key's doc
// comment for why this dedicated client is unavoidable.
func patchConformanceASConfig(path string, p profile, pub1, pub2, pubRS256 jwks) (clientIDs [2]string, rs256ClientID string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return clientIDs, "", err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return clientIDs, "", fmt.Errorf("parse: %w", err)
	}
	var clients []map[string]json.RawMessage
	if err := json.Unmarshal(top["clients"], &clients); err != nil {
		return clientIDs, "", fmt.Errorf("parse clients: %w", err)
	}
	if len(clients) != 2 && len(clients) != 3 {
		return clientIDs, "", fmt.Errorf("expected 2 or 3 clients, found %d", len(clients))
	}

	newJWKS := [2]jwks{pub1, pub2}
	for i := range 2 {
		var id string
		if err := json.Unmarshal(clients[i]["id"], &id); err != nil {
			return clientIDs, "", fmt.Errorf("parse clients[%d].id: %w", i, err)
		}
		clientIDs[i] = id

		encoded, err := json.Marshal(newJWKS[i])
		if err != nil {
			return clientIDs, "", err
		}
		clients[i]["jwks"] = encoded
	}

	if len(clients) == 3 {
		if err := json.Unmarshal(clients[2]["id"], &rs256ClientID); err != nil {
			return clientIDs, "", fmt.Errorf("parse clients[2].id: %w", err)
		}
		encoded, err := json.Marshal(pubRS256)
		if err != nil {
			return clientIDs, "", err
		}
		clients[2]["jwks"] = encoded
	} else {
		rs256ClientID = "gofapi-conformance-" + p.keyLabel1 + "-rs256-client"
		callback := "https://localhost.emobix.co.uk:8443/test/a/" + p.alias + "/callback"
		newClient := map[string]any{
			"id":                         rs256ClientID,
			"redirect_uris":              []string{callback, callback + "?dummy1=lorem&dummy2=ipsum"},
			"client_assertion_algorithm": "PS256",
			"request_object_algorithm":   "PS256",
			"allowed_scopes":             []string{"openid", "accounts", "offline_access"},
			"jwks":                       pubRS256,
		}
		encoded, err := marshalIndentNoEscape(newClient)
		if err != nil {
			return clientIDs, "", err
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &raw); err != nil {
			return clientIDs, "", err
		}
		clients = append(clients, raw)
	}

	encodedClients, err := marshalIndentNoEscape(clients)
	if err != nil {
		return clientIDs, "", err
	}
	top["clients"] = encodedClients

	if err := ensureAlgorithm(top, "client_assertion", "PS256"); err != nil {
		return clientIDs, "", err
	}
	if p.name == "message-signing" {
		if err := ensureAlgorithm(top, "request_object", "PS256"); err != nil {
			return clientIDs, "", err
		}
	}

	out, err := marshalIndentNoEscape(top)
	if err != nil {
		return clientIDs, "", err
	}
	out = append(out, '\n')
	return clientIDs, rs256ClientID, os.WriteFile(path, out, 0o644)
}

// ensureAlgorithm appends alg to top["algorithms"][field] (a JSON
// array of strings) if it isn't already present, in place.
func ensureAlgorithm(top map[string]json.RawMessage, field, alg string) error {
	var algorithms map[string]json.RawMessage
	if err := json.Unmarshal(top["algorithms"], &algorithms); err != nil {
		return fmt.Errorf("parse algorithms: %w", err)
	}
	var set []string
	if err := json.Unmarshal(algorithms[field], &set); err != nil {
		return fmt.Errorf("parse algorithms.%s: %w", field, err)
	}
	for _, a := range set {
		if a == alg {
			return nil
		}
	}
	set = append(set, alg)
	encoded, err := json.Marshal(set)
	if err != nil {
		return err
	}
	algorithms[field] = encoded
	encodedAlgorithms, err := json.Marshal(algorithms)
	if err != nil {
		return err
	}
	top["algorithms"] = encodedAlgorithms
	return nil
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
	Browser []browserBlock `json:"browser,omitempty"`

	// Client, when set, replaces the plan's top-level "client" block
	// wholesale for exactly this one test module — see
	// ensure-signed-{client-assertion,request-object}-with-RS256-fails'
	// override entries below for why this exists and why it must
	// *replace* rather than add to client.jwks.
	Client *planClient `json:"client,omitempty"`
}

func writePlanConfig(path string, p profile, clientIDs [2]string, rs256ClientID string, priv1, priv2, privRS256 jwks) error {
	authorizeURL := "https://" + p.issuerHost + ":8443/authorize*"
	trueVal := true
	one := 1

	consentTask := browserTask{
		Task: "Consent", Match: authorizeURL, Optional: &trueVal,
		Commands: [][]string{{"click", "xpath", "//button[@name='decision' and @value='approve']", "optional"}},
	}
	consentBlock := browserBlock{Match: authorizeURL, Tasks: []browserTask{consentTask}}

	// ensure-signed-{client-assertion,request-object}-with-RS256-fails
	// each need client.jwks.keys[0].alg to be exactly "PS256" just to
	// start running at all (otherwise they SKIP outright — see
	// generatePS256Key's own doc comment) — and, per that same doc
	// comment, need to authenticate PAR (and, for the request-object
	// module, sign a valid request object) as a client actually
	// *registered* for PS256, not just present a PS256-shaped key from
	// an ES256-registered client. Scoping a dedicated client override
	// — switching client_id to the third, PS256-only client
	// (patchConformanceASConfig) for just
	// these two test names — keeps every other module in the plan on
	// client1/client2 exactly as before; nothing else ever sees this
	// third client or its key.
	rs256Client := &planClient{
		ClientID: rs256ClientID, Scope: "openid accounts offline_access", JWKS: privRS256, DPoPSigningAlg: "ES256",
	}

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
		"fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails": {Client: rs256Client},
	}
	if p.name == "message-signing" {
		// Only reachable under a profile that actually sends signed
		// request objects — see expected-skips-message-signing.json's
		// own comment for why this doesn't appear in the baseline
		// plan at all.
		cfg.Override["fapi2-security-profile-final-ensure-signed-request-object-with-RS256-fails"] = overrideEntry{Client: rs256Client}
	}
	cfg.Options.BrowsercontrolCSSEnable = false

	out, err := marshalIndentNoEscape(cfg)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}
