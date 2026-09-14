// Command setup-config bootstraps everything a fresh clone needs to run
// the AS-side conformance suites (conformance/scripts/run-all.sh's "AS
// baseline", "AS message-signing", "AS ciba-mtls", "AS ciba-ping", "AS
// mtls", "AS message-signing-mtls", "AS client-auth-mtls", "AS
// client-auth-mtls-and-mtls", "AS ciba-client-auth-mtls", and "AS
// ciba-ping-client-auth-mtls" legs) that isn't already committed to
// this repo.
//
// Two files per profile can't be committed at all:
// conformance/server/oidf-config/{baseline,message-signing,ciba,ciba-mtls,ciba-ping,mtls,message-signing-mtls,client-auth-mtls,client-auth-mtls-and-mtls,ciba-client-auth-mtls,ciba-ping-client-auth-mtls}-plan.json
// (the OIDF conformance suite's own plan config) are gitignored because
// they carry the test client's *private* JWKS keys or mTLS certificate
// keys — see this repo's conformance/server/oidf-config/README.md and
// .gitignore's own comment. This tool generates a fresh ES256 keypair
// per client per profile (RSA/PS256 for ciba-mtls's client1; a
// throwaway self-signed mTLS certificate per client for ciba-mtls,
// ciba-ping, mtls, message-signing-mtls, client-auth-mtls,
// client-auth-mtls-and-mtls, ciba-client-auth-mtls, and
// ciba-ping-client-auth-mtls alike — see
// setupCIBAMTLS/setupCIBAPing/writePlanConfig's own
// senderConstrainMTLS branch/setupClientAuthMTLSVariant),
// writes the private half into the (gitignored) plan config alongside
// everything else that config needs — alias, discovery URL, resource
// block, and the browser/override automation this repo's own
// conformance work has already worked out and documented — and writes
// the matching public half (or, for client-auth-mtls, the certificate's
// RFC 8705 thumbprint) into this repo's own (committed) conformance-as
// config file for that profile, so the two stay in sync.
//
// Idempotent, and self-healing rather than a pure no-op: if a profile's
// plan config already exists, this tool never regenerates or
// overwrites its key/certificate material (a working local setup, or
// one already loaded into a live suite run, is never invalidated) —
// but it always re-derives the public half (or certificate thumbprint)
// from whatever that existing plan currently holds and re-patches the
// committed config file to match, on every run, rather than trusting
// the plan file's mere presence as proof the two are still in sync.
// That sync can otherwise drift silently: anything that changes the
// committed config file afterward (a teammate's own setup-config run,
// a merge, a manual edit) leaves an already-generated local plan
// signing with a private key whose public half no longer matches what
// the AS has registered, and every request that client makes then
// fails client-assertion (or certificate) verification — confirmed
// live. Run it again after a `git clean` or on a fresh clone to
// generate what's missing from scratch; run it again any other time
// to heal exactly this drift.
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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/idfoundry/fapigo/internal/mtls"
)

// profile is everything that differs between the baseline,
// message-signing, and mTLS-sender-constrained conformance-suite plans.
type profile struct {
	name       string // matches the *-plan.json / *.config.json filename prefix
	alias      string // suite plan "alias" — also the callback path segment
	issuerHost string // docker-compose service name this profile's AS listens as
	keyLabel1  string // generate-client-key-style label for client 1
	keyLabel2  string // generate-client-key-style label for client 2

	// senderConstrainMTLS marks a profile whose clients are registered
	// storage.SenderConstrainMTLS (RFC 8705 §3) instead of the default
	// DPoP — writePlanConfig additionally generates and embeds a
	// suite-side mTLS client certificate pair (mtls/mtls2) for these,
	// mirroring setupCIBAMTLS's own identical need. "mtls" and
	// "message-signing-mtls" close a real coverage gap: AS ciba-mtls
	// exercises mTLS-bound tokens but never PAR/authorize (CIBA has no
	// browser hop at all), while AS client-auth-mtls exercises the full
	// PAR/authorize/token flow under mTLS but only for RFC 8705 §2
	// *client authentication* — sender-constraining stays DPoP there.
	// Neither combination — the ordinary PAR/authorize/token flow with
	// mTLS-bound *access tokens* — had ever been live-conformance-tested
	// until these two profiles, confirmed live: fapi2-security-profile-final-test-plan
	// genuinely accepts sender_constrain=mtls as a variant.
	senderConstrainMTLS bool
}

var profiles = []profile{
	{name: "baseline", alias: "gofapi-baseline", issuerHost: "conformance-as-baseline", keyLabel1: "client1", keyLabel2: "client2"},
	{name: "message-signing", alias: "gofapi-msgsign", issuerHost: "conformance-as-message-signing", keyLabel1: "msgsign-client1", keyLabel2: "msgsign-client2"},
	{name: "mtls", alias: "gofapi-mtls", issuerHost: "conformance-as-mtls", keyLabel1: "mtls-client1", keyLabel2: "mtls-client2", senderConstrainMTLS: true},
	{name: "message-signing-mtls", alias: "gofapi-msgsign-mtls", issuerHost: "conformance-as-message-signing-mtls", keyLabel1: "msgsign-mtls-client1", keyLabel2: "msgsign-mtls-client2", senderConstrainMTLS: true},
}

// conformanceKeyLabelPrefix prefixes every kid/key-label this tool
// generates, distinguishing them from any other key a shared suite
// instance or AS deployment might hold.
const conformanceKeyLabelPrefix = "gofapi-conformance-"

// fullScope is every scope this tool's clients register for — the
// suite plan needs it for client, client2 and the PS256-only override
// client alike.
const fullScope = "openid accounts offline_access"

// rs256ClientAssertionOverrideKey is the suite test-module name
// writePlanConfig keys its RS256-override entry under — named here too
// so the main loop's resync path can read the same override entry's
// own Client.JWKS back out of an already-existing plan config.
const rs256ClientAssertionOverrideKey = "fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails"

// wellKnownConfigPath, userinfoPath, backchannelApprovalPath, and
// cibaApprovalQuery are path/query fragments every profile's own
// setupXxx function builds a URL from — shared here rather than
// repeated per profile to avoid a typo diverging one profile's URL
// shape from the others'.
const (
	wellKnownConfigPath = "/.well-known/openid-configuration"
	userinfoPath        = "/userinfo"
	// accountsPath is cmd/conformance-as's own non-OIDC protected
	// -resource endpoint (accountsHandler) — only the
	// client-credentials profiles' Resource.ResourceURL uses this
	// instead of userinfoPath, since a client_credentials-issued token
	// can validly carry no "openid" scope at all (confirmed live: the
	// suite forbids requesting "openid" under openid=plain_oauth, the
	// only legal variant value for fapi_profile=fapi_client_credentials_grant),
	// but /userinfo requires it. See accountsHandler's own doc comment.
	accountsPath            = "/accounts"
	backchannelApprovalPath = "/backchannel-approve"
	cibaApprovalQuery       = "?auth_req_id={auth_req_id}&action={action}"
)

// conformanceTestSubject and silverACR are the fixed subject/ACR value
// every CIBA-capable profile's plan uses to drive its own automated
// approval — see setupCIBA/setupCIBAMTLS/setupCIBAPing.
const (
	conformanceTestSubject = "conformance-test-user"
	silverACR              = "urn:mace:incommon:iap:silver"
)

// mtlsSuiteClientCNSuffix/mtlsSuiteClient2CNSuffix name the suite's own
// throwaway mTLS client certificates (generateMTLSCertKeyPEM's
// commonName argument) — shared across every senderConstrainMTLS-ish
// profile (ciba-mtls, ciba-ping, client-auth-mtls, mtls,
// message-signing-mtls) rather than repeated per profile.
const (
	mtlsSuiteClientCNSuffix  = "-suite-client"
	mtlsSuiteClient2CNSuffix = "-suite-client2"
)

// issuerURL builds one of this profile's AS URLs — every plan/config
// field that names one shares the same host:8443 base, just a
// different path.
func issuerURL(host, path string) string {
	return "https://" + host + ":8443" + path
}

// mtlsURL is issuerURL's RFC 8705 §3 counterpart: the same host, but
// the mTLS listener's own port (8444) — every senderConstrainMTLS
// profile's own resource URL needs this, not issuerURL's plain :8443
// (a client presenting its certificate to the plain listener, which
// never asks for one, gets a token the resource endpoint's own binding
// check then rejects — see ARCHITECTURE.md's mtls/message-signing-mtls
// account).
func mtlsURL(host, path string) string {
	return "https://" + host + ":8444" + path
}

func main() {
	dir, err := oidfConfigDir()
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range profiles {
		planPath := filepath.Join(dir, p.name+"-plan.json")
		configPath := filepath.Join(dir, p.name+".config.json")

		existing, planExists, err := loadExistingPlan[planConfig](planPath)
		if err != nil {
			log.Fatalf("%s: %v", p.name, err)
		}

		var priv1, priv2, privRS256 jwks
		if planExists {
			priv1, priv2 = existing.Client.JWKS, existing.Client2.JWKS
			if override, ok := existing.Override[rs256ClientAssertionOverrideKey]; ok && override.Client != nil {
				privRS256 = override.Client.JWKS
			}
			if err := requireNonEmptyPrivateKey(priv1, planPath+": client"); err != nil {
				log.Fatalf("%s: %v", p.name, err)
			}
			if err := requireNonEmptyPrivateKey(priv2, planPath+": client2"); err != nil {
				log.Fatalf("%s: %v", p.name, err)
			}
			if err := requireNonEmptyPrivateKey(privRS256, planPath+": override RS256 client"); err != nil {
				log.Fatalf("%s: %v", p.name, err)
			}
		} else {
			priv1, _, err = generateKey(p.keyLabel1)
			if err != nil {
				log.Fatalf("%s: generate client1 key: %v", p.name, err)
			}
			priv2, _, err = generateKey(p.keyLabel2)
			if err != nil {
				log.Fatalf("%s: generate client2 key: %v", p.name, err)
			}
			privRS256, _, err = generatePS256Key(conformanceKeyLabelPrefix + p.keyLabel1 + "-rs256-key1")
			if err != nil {
				log.Fatalf("%s: generate RS256 test-client key: %v", p.name, err)
			}
		}
		pub1, pub2, pubRS256 := publicOnly(priv1), publicOnly(priv2), publicOnly(privRS256)

		clientIDs, rs256ClientID, err := patchConformanceASConfig(configPath, p, pub1, pub2, pubRS256)
		if err != nil {
			log.Fatalf("%s: update %s: %v", p.name, configPath, err)
		}

		if planExists {
			fmt.Printf("%s: %s already exists — resynced %s's public keys to match it\n", p.name, planPath, configPath)
			continue
		}
		if err := writePlanConfig(planPath, p, clientIDs, rs256ClientID, priv1, priv2, privRS256); err != nil {
			log.Fatalf("%s: write %s: %v", p.name, planPath, err)
		}
		fmt.Printf("%s: generated fresh client keys, wrote %s and updated %s\n", p.name, planPath, configPath)
	}

	if err := setupCIBA(dir); err != nil {
		log.Fatalf("ciba: %v", err)
	}

	if err := setupCIBAMTLS(dir); err != nil {
		log.Fatalf("ciba-mtls: %v", err)
	}

	// Must run after setupCIBAMTLS: appendCIBAPingClients reads
	// ciba-mtls.config.json's existing "clients" array and appends to
	// it, so the two poll-mode clients setupCIBAMTLS manages there must
	// already exist.
	if err := setupCIBAPing(dir); err != nil {
		log.Fatalf("ciba-ping: %v", err)
	}

	if err := setupClientAuthMTLSVariant(dir, "client-auth-mtls", false); err != nil {
		log.Fatalf("client-auth-mtls: %v", err)
	}

	if err := setupClientAuthMTLSVariant(dir, "client-auth-mtls-and-mtls", true); err != nil {
		log.Fatalf("client-auth-mtls-and-mtls: %v", err)
	}

	// Must run after setupCIBAMTLS: both add clients to the same
	// committed ciba-mtls.config.json, the same ordering constraint
	// setupCIBAPing already has above.
	if err := setupCIBAClientAuthMTLSVariant(dir, "client-auth-mtls", ""); err != nil {
		log.Fatalf("ciba-client-auth-mtls: %v", err)
	}
	if err := setupCIBAClientAuthMTLSVariant(dir, "ping-client-auth-mtls", "ping"); err != nil {
		log.Fatalf("ciba-ping-client-auth-mtls: %v", err)
	}

	// Must run after the profiles/setupClientAuthMTLSVariant loops
	// above: each of these appends one more client to a config.json one
	// of those already wrote.
	for _, c := range clientCredentialsGrantContainers {
		if err := setupClientCredentialsGrantVariant(dir, c.baseName, c.clientAuthMTLS, c.senderConstrainMTLS); err != nil {
			log.Fatalf("%s-client-credentials: %v", c.baseName, err)
		}
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
	kid := conformanceKeyLabelPrefix + label + "-key1"
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

// publicOnly returns ks with every key's private components cleared —
// the exact inverse of generateKey/generatePS256Key's own
// private/public split (each private jwk is just the public one plus
// D, or plus D/P/Q/DP/DQ/QI for RSA). This lets every setupXxx
// function below re-derive the public half it needs to patch into a
// committed config.json straight from a plan config's own
// already-generated private key material, without ever touching
// crypto/* again — see loadExistingPlan's own doc comment for why this
// matters.
func publicOnly(ks jwks) jwks {
	pub := jwks{Keys: make([]jwk, len(ks.Keys))}
	for i, k := range ks.Keys {
		k.D, k.P, k.Q, k.DP, k.DQ, k.QI = "", "", "", "", "", ""
		pub.Keys[i] = k
	}
	return pub
}

// requireNonEmptyPrivateKey fails loudly if ks doesn't actually carry
// private key material — guards against silently proceeding with a
// corrupted or hand-edited plan config on the resync path below,
// rather than writing an obviously-broken keypair into a committed
// config.json.
func requireNonEmptyPrivateKey(ks jwks, context string) error {
	if len(ks.Keys) == 0 || ks.Keys[0].D == "" {
		return fmt.Errorf("%s: missing or empty private key material", context)
	}
	return nil
}

// loadExistingPlan reads path and unmarshals it into T, reporting
// exists=false (not an error) only when the file is genuinely absent —
// every other read or parse failure is a hard error, since a plan file
// that exists but can't be understood must never be silently treated
// as safe to leave alone.
//
// This is the fix for a real, confirmed-live bug: every setupXxx
// function below used to skip regenerating anything at all once its
// own plan-*.json existed, on the theory that "the plan and the
// committed config.json it patches were written together, so they're
// still in sync." That's false the moment anything else changes the
// committed config.json afterward (a teammate's own setup-config run,
// a merge, a manual edit) — the local, gitignored plan file then
// silently signs with a private key whose public half no longer
// matches what's registered, and every request that client makes fails
// client-assertion (or certificate) verification. Reading the existing
// plan's own key material back out and re-patching config.json from it
// on every run — instead of skipping when the plan file merely exists —
// makes setup-config self-healing against exactly that drift, without
// ever needing to regenerate (and thereby invalidate) a plan a
// developer already has loaded into a live suite run.
func loadExistingPlan[T any](path string) (cfg T, exists bool, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is this dev-only script's own fixed CLI argument, not untrusted input
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, false, nil
		}
		return cfg, false, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, false, fmt.Errorf("parse existing %s: %w", path, err)
	}
	return cfg, true, nil
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
	data, err := os.ReadFile(path) // #nosec G304 -- path is this dev-only script's own fixed CLI argument, not untrusted input
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
	// Only requires *at least* 2 clients, not exactly 2 or 3 — the same
	// "trailing clients this function doesn't own are safe to leave
	// untouched" reasoning patchCIBAMTLSConfig's own doc comment
	// explains: on a fresh clone this runs (baseline-plan.json etc. are
	// gitignored, so the caller's already-exists guard never fires)
	// against the already-committed config.json, which
	// setupClientCredentialsGrantVariant has since grown to 5 entries
	// for baseline/mtls (client1, client2, the RS256 client, and two
	// client_credentials clients) — this function only ever reads/writes
	// index 0, 1, and conditionally 2, so anything beyond that is safe
	// to leave alone.
	if len(clients) < 2 {
		return clientIDs, "", fmt.Errorf("expected at least 2 clients, found %d", len(clients))
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

	if len(clients) >= 3 {
		// A third-or-later client already exists — position 2 is always
		// the RS256/PS256 client specifically (the only one this or any
		// other setup function ever inserts there; anything at index 3+
		// is a later feature's own append, e.g. client_credentials'
		// two clients, left untouched below).
		if err := json.Unmarshal(clients[2]["id"], &rs256ClientID); err != nil {
			return clientIDs, "", fmt.Errorf("parse clients[2].id: %w", err)
		}
		encoded, err := json.Marshal(pubRS256)
		if err != nil {
			return clientIDs, "", err
		}
		clients[2]["jwks"] = encoded
	} else {
		rs256ClientID = conformanceKeyLabelPrefix + p.keyLabel1 + "-rs256-client"
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

	// No algorithms patching needed here (unlike before
	// cmd/conformance-as switched to server.RecommendedAlgorithms()
	// unconditionally): the recommended default already includes PS256
	// in both ClientAssertion and RequestObject, so the dedicated
	// PS256/RS256-negative-test client above is already accepted by the
	// server-wide algorithm policy without widening anything.

	out, err := marshalIndentNoEscape(top)
	if err != nil {
		return clientIDs, "", err
	}
	out = append(out, '\n')
	return clientIDs, rs256ClientID, os.WriteFile(path, out, 0o644) // #nosec G306 -- this AS's own config.json carries only public keys (oidf-config/README.md), meant to be world-readable
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
	// MTLS/MTLS2 are only ever set for a profile with
	// senderConstrainMTLS true — pointers with omitempty so
	// baseline/message-signing's own plan.json output stays exactly as
	// it already was, byte for byte, when unset.
	MTLS     *mtlsBlock `json:"mtls,omitempty"`
	MTLS2    *mtlsBlock `json:"mtls2,omitempty"`
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

// baseOverrides returns the two override entries every plan config in
// this tool needs regardless of client-authentication method: deny the
// "user-rejects-authentication" module's consent, and limit the
// reused-request-uri module to exactly one authorize visit before its
// own retry visits consentBlock again.
func baseOverrides(authorizeURL string, consentBlock browserBlock, matchLimit *int) map[string]overrideEntry {
	return map[string]overrideEntry{
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
				{Match: authorizeURL, MatchLimit: matchLimit, Tasks: []browserTask{}},
				consentBlock,
			},
		},
	}
}

func writePlanConfig(path string, p profile, clientIDs [2]string, rs256ClientID string, priv1, priv2, privRS256 jwks) error {
	authorizeURL := issuerURL(p.issuerHost, "/authorize*")
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
		ClientID: rs256ClientID, Scope: fullScope, JWKS: privRS256, DPoPSigningAlg: "ES256",
	}

	cfg := planConfig{Alias: p.alias}
	cfg.Server.DiscoveryURL = issuerURL(p.issuerHost, wellKnownConfigPath)
	if p.senderConstrainMTLS {
		mtlsCert, mtlsKey, err := generateMTLSCertKeyPEM(p.alias + mtlsSuiteClientCNSuffix)
		if err != nil {
			return fmt.Errorf("generate client1 mtls certificate: %w", err)
		}
		mtls2Cert, mtls2Key, err := generateMTLSCertKeyPEM(p.alias + mtlsSuiteClient2CNSuffix)
		if err != nil {
			return fmt.Errorf("generate client2 mtls certificate: %w", err)
		}
		cfg.MTLS = &mtlsBlock{Cert: mtlsCert, Key: mtlsKey}
		cfg.MTLS2 = &mtlsBlock{Cert: mtls2Cert, Key: mtls2Key}
	}
	cfg.Client = planClient{ClientID: clientIDs[0], Scope: fullScope, JWKS: priv1, DPoPSigningAlg: "ES256"}
	cfg.Client2 = planClient{ClientID: clientIDs[1], Scope: fullScope, JWKS: priv2, DPoPSigningAlg: "ES256"}
	if p.senderConstrainMTLS {
		// Port 8444, not 8443: RFC 8705 sender-constraining means this
		// resource call must go over the mTLS listener itself — mirrors
		// setupCIBAMTLS's own identical reasoning. Confirmed live: the
		// resource endpoint otherwise rejects the mTLS-bound access
		// token's certificate binding check with 400, since the
		// connection carries no client certificate at all on :8443.
		cfg.Resource.ResourceURL = mtlsURL(p.issuerHost, userinfoPath)
	} else {
		cfg.Resource.ResourceURL = issuerURL(p.issuerHost, userinfoPath)
	}
	cfg.Browser = []browserBlock{consentBlock}
	cfg.Override = baseOverrides(authorizeURL, consentBlock, &one)
	cfg.Override[rs256ClientAssertionOverrideKey] = overrideEntry{Client: rs256Client}
	if p.name == "message-signing" || p.name == "message-signing-mtls" {
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
	// Unlike patchConformanceASConfig's config.json, this plan.json
	// embeds the suite-side test clients' own private keys (priv1/
	// priv2/privRS256 above) - throwaway/ephemeral, but still real key
	// material, so it's written owner-only rather than world-readable.
	return os.WriteFile(path, out, 0o600)
}

// cibaClient/cibaClient2/cibaPlan mirror the OIDF conformance suite's
// own plan config shape for the FAPI-CIBA-ID1 plan
// (net.openid.conformance.fapiciba.AbstractFAPICIBAID1's own
// @ConfigurationFields) — a genuinely different shape from
// planConfig/planClient above, since CIBA has no browser step at all
// (no authorize/consent redirect to automate) and needs its own
// fields (hint_type/hint_value identify who's authenticating;
// automated_ciba_approval_url is the suite's own documented mechanism
// for driving an approve/deny decision with no real out-of-band device
// to click through — see cmd/conformance-as/backchannel.go's
// handleApprove).
type cibaClient struct {
	ClientID       string `json:"client_id"`
	Scope          string `json:"scope"`
	JWKS           jwks   `json:"jwks"`
	DPoPSigningAlg string `json:"dpop_signing_alg"`
	HintType       string `json:"hint_type"`
	HintValue      string `json:"hint_value"`
}

type cibaClient2 struct {
	ClientID       string `json:"client_id"`
	Scope          string `json:"scope"`
	JWKS           jwks   `json:"jwks"`
	DPoPSigningAlg string `json:"dpop_signing_alg"`
	ACRValue       string `json:"acr_value"`
}

type cibaPlan struct {
	Alias  string `json:"alias"`
	Server struct {
		DiscoveryURL string `json:"discoveryUrl"`
	} `json:"server"`
	Client   cibaClient  `json:"client"`
	Client2  cibaClient2 `json:"client2"`
	Resource struct {
		ResourceURL string `json:"resourceUrl"`
	} `json:"resource"`
	AutomatedCibaApprovalURL string `json:"automated_ciba_approval_url"`
}

// setupCIBA is the CIBA-plan counterpart of the profiles loop in main —
// factored out separately (rather than added as a third profiles[]
// entry) because writeCIBAPlanConfig's output shape is unrelated to
// writePlanConfig's, not just a variation of it. Idempotent the same
// way — see the package doc comment: never regenerates an existing
// ciba-plan.json's own keys, but always resyncs ciba.config.json's
// public keys to match whatever it currently holds.
//
// Reuses patchConformanceASConfig as-is against ciba.config.json's own
// three clients (client1/client2/a PS256-registered third client) —
// that function's own contract (exactly 2 or 3 clients, patch the
// first two, add-or-refresh a third PS256 one) applies unchanged here.
// The PS256 client's key is generated but not referenced by this
// plan's own JSON: unlike the base FAPI2SPFinal plan, FAPI-CIBA-ID1's
// two RS256-client-assertion negative tests
// (fapi-ciba-id1-ensure-client-assertion-signature-algorithm-in-
// {backchannel-authorization-request,token-endpoint-request}-is-RS256-fails)
// each check the plan's own client.jwks.keys[0].alg and SKIP outright
// (not fail) when it isn't already "PS256" — a legitimate, honest
// outcome this first pass accepts rather than adding a client-override
// block to force them to run.
func setupCIBA(dir string) error {
	planPath := filepath.Join(dir, "ciba-plan.json")
	p := profile{name: "ciba", alias: "gofapi-ciba", issuerHost: "conformance-as-ciba", keyLabel1: "ciba-client1", keyLabel2: "ciba-client2"}

	existing, planExists, err := loadExistingPlan[cibaPlan](planPath)
	if err != nil {
		return err
	}

	var priv1, priv2 jwks
	if planExists {
		priv1, priv2 = existing.Client.JWKS, existing.Client2.JWKS
		if err := requireNonEmptyPrivateKey(priv1, planPath+": client"); err != nil {
			return err
		}
		if err := requireNonEmptyPrivateKey(priv2, planPath+": client2"); err != nil {
			return err
		}
	} else {
		priv1, _, err = generateKey(p.keyLabel1)
		if err != nil {
			return fmt.Errorf("generate client1 key: %w", err)
		}
		priv2, _, err = generateKey(p.keyLabel2)
		if err != nil {
			return fmt.Errorf("generate client2 key: %w", err)
		}
	}
	pub1, pub2 := publicOnly(priv1), publicOnly(priv2)

	configPath := filepath.Join(dir, "ciba.config.json")

	// This third client's own key is never referenced by ciba-plan.json
	// at all (see this function's own package doc comment) — nothing
	// ever compares it to a private counterpart, so there's no existing
	// plan to recover it from. Reuse whatever's already committed in
	// config.json when there is one, purely to avoid a needless key
	// rotation (and the resulting no-op-looking git diff) on every run;
	// mint a fresh one only the first time.
	pubRS256, ok := existingThirdClientPublicKey(configPath)
	if !ok {
		_, pubRS256, err = generatePS256Key(conformanceKeyLabelPrefix + p.keyLabel1 + "-rs256-key1")
		if err != nil {
			return fmt.Errorf("generate RS256 test-client key: %w", err)
		}
	}

	clientIDs, _, err := patchConformanceASConfig(configPath, p, pub1, pub2, pubRS256)
	if err != nil {
		return fmt.Errorf("update %s: %w", configPath, err)
	}

	if planExists {
		fmt.Printf("ciba: %s already exists — resynced %s's public keys to match it\n", planPath, configPath)
		return nil
	}

	cfg := cibaPlan{Alias: p.alias}
	cfg.Server.DiscoveryURL = issuerURL(p.issuerHost, wellKnownConfigPath)
	cfg.Client = cibaClient{
		ClientID: clientIDs[0], Scope: fullScope, JWKS: priv1, DPoPSigningAlg: "ES256",
		HintType: "login_hint", HintValue: conformanceTestSubject,
	}
	cfg.Client2 = cibaClient2{
		ClientID: clientIDs[1], Scope: fullScope, JWKS: priv2, DPoPSigningAlg: "ES256",
		ACRValue: silverACR,
	}
	cfg.Resource.ResourceURL = issuerURL(p.issuerHost, userinfoPath)
	cfg.AutomatedCibaApprovalURL = issuerURL(p.issuerHost, backchannelApprovalPath) + cibaApprovalQuery

	out, err := marshalIndentNoEscape(cfg)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(planPath, out, 0o600); err != nil { // #nosec G306 -- mirrors writePlanConfig's own owner-only rationale (embeds priv1/priv2)
		return err
	}
	fmt.Printf("ciba: generated fresh client keys, wrote %s and updated %s\n", planPath, configPath)
	return nil
}

// mtlsBlock is one PEM cert+key pair — the suite plan config's own
// "mtls"/"mtls2" top-level shape (net.openid.conformance.fapiciba's own
// ExtractMTLSCertificatesFromConfiguration/ExtractMTLSCertificates2FromConfiguration,
// confirmed by disassembly during this profile's original live
// investigation — one block per client, not documented in any bundled
// sample config) for the suite's own outbound TLS client to present.
type mtlsBlock struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// cibaMTLSClient/cibaMTLSClient2 mirror cibaClient/cibaClient2 exactly,
// minus DPoPSigningAlg — an mTLS-sender-constrained client never builds
// a DPoP proof at all, so this plan carries no such field for either
// client.
type cibaMTLSClient struct {
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	JWKS      jwks   `json:"jwks"`
	HintType  string `json:"hint_type"`
	HintValue string `json:"hint_value"`
}

type cibaMTLSClient2 struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	JWKS     jwks   `json:"jwks"`
	ACRValue string `json:"acr_value"`
}

type cibaMTLSPlan struct {
	Alias  string `json:"alias"`
	Server struct {
		DiscoveryURL string `json:"discoveryUrl"`
	} `json:"server"`
	MTLS     mtlsBlock       `json:"mtls"`
	MTLS2    mtlsBlock       `json:"mtls2"`
	Client   cibaMTLSClient  `json:"client"`
	Client2  cibaMTLSClient2 `json:"client2"`
	Resource struct {
		ResourceURL string `json:"resourceUrl"`
	} `json:"resource"`
	AutomatedCibaApprovalURL string `json:"automated_ciba_approval_url"`
}

// generateMTLSCertKeyPEM generates a throwaway, self-signed ECDSA P-256
// client certificate — the suite-side counterpart of
// cmd/conformance-client/mtls.go's own selfSignedClientCert, except
// this one needs a long validity window (a plan config committed to a
// developer's own local setup and reused across many runs, unlike that
// driver's fresh-per-process throwaway) rather than a one-hour one.
func generateMTLSCertKeyPEM(commonName string) (certPEM, keyPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", "", fmt.Errorf("generate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}

// patchCIBAMTLSConfig replaces clients[0].jwks and clients[1].jwks in
// the committed ciba-mtls.config.json with pubRSA/pubEC, leaving every
// other field — including sender_constrain, client_assertion_algorithm,
// redirect_uris — exactly as it already was, the same
// preserve-what-this-tool-doesn't-own approach
// patchConformanceASConfig uses. Simpler than that function: this
// profile's two clients need no third PS256-only client of their own
// (client1 is already RSA/PS256 — see oidf-config/README.md's own
// account of why that alone was enough to un-SKIP the RS256 modules
// here). Only requires *at least* 2 clients, not exactly 2: on a fresh
// clone this runs (ciba-mtls-plan.json is gitignored, so its
// already-exists guard never fires) against the already-committed
// ciba-mtls.config.json, which setupCIBAPing's appendCIBAPingClients
// has since grown to 4 entries — this function only ever reads/writes
// index 0 and 1, so those trailing ciba-ping clients are safe to leave
// untouched.
// readConfigClients reads path (one of this tool's committed
// conformance-as config.json files) and returns its top-level object
// plus its "clients" array, both as json.RawMessage-valued maps so a
// caller can patch or append individual client fields without
// disturbing whatever this tool doesn't own — the shared first step
// every patch/append function below needs.
func readConfigClients(path string) (top map[string]json.RawMessage, clients []map[string]json.RawMessage, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is this dev-only script's own fixed CLI argument, not untrusted input
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, nil, fmt.Errorf("parse: %w", err)
	}
	if err := json.Unmarshal(top["clients"], &clients); err != nil {
		return nil, nil, fmt.Errorf("parse clients: %w", err)
	}
	return top, clients, nil
}

// existingThirdClientPublicKey returns the jwks of path's own third
// client entry, if path already exists and already has one. setupCIBA
// uses this to avoid a needless key rotation every run on a public key
// nothing ever checks against anything (see its own doc comment for
// why): once a valid one is already committed, reusing it instead of
// minting a fresh replacement keeps a clean run-twice-get-no-diff
// property everywhere else in this file already has.
func existingThirdClientPublicKey(path string) (pub jwks, ok bool) {
	_, clients, err := readConfigClients(path)
	if err != nil || len(clients) < 3 {
		return jwks{}, false
	}
	if err := json.Unmarshal(clients[2]["jwks"], &pub); err != nil || len(pub.Keys) == 0 {
		return jwks{}, false
	}
	return pub, true
}

func patchCIBAMTLSConfig(path string, pubRSA, pubEC jwks) (clientIDs [2]string, err error) {
	top, clients, err := readConfigClients(path)
	if err != nil {
		return clientIDs, err
	}
	if len(clients) < 2 {
		return clientIDs, fmt.Errorf("expected at least 2 clients, found %d", len(clients))
	}

	newJWKS := [2]jwks{pubRSA, pubEC}
	for i := range 2 {
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

	encodedClients, err := marshalIndentNoEscape(clients)
	if err != nil {
		return clientIDs, err
	}
	top["clients"] = encodedClients

	out, err := marshalIndentNoEscape(top)
	if err != nil {
		return clientIDs, err
	}
	out = append(out, '\n')
	return clientIDs, os.WriteFile(path, out, 0o644) // #nosec G306 -- this AS's own config.json carries only public keys (oidf-config/README.md), meant to be world-readable
}

// setupCIBAMTLS is setupCIBA's mTLS-sender-constrained counterpart —
// factored out separately rather than folded into setupCIBA itself,
// since the two profiles' plan shapes and client key types genuinely
// differ (RSA/PS256 client1 + EC/ES256 client2 here, vs ES256-only
// there; mtls/mtls2 cert blocks here, dpop_signing_alg there), not just
// a parameter away from each other. Idempotent the same way — see the
// package doc comment: never regenerates an existing ciba-mtls-plan.json's
// own keys, but always resyncs ciba-mtls.config.json's public keys to
// match whatever it currently holds.
func setupCIBAMTLS(dir string) error {
	planPath := filepath.Join(dir, "ciba-mtls-plan.json")
	const alias = "gofapi-ciba-mtls"
	const issuerHost = "conformance-as-ciba-mtls"

	existing, planExists, err := loadExistingPlan[cibaMTLSPlan](planPath)
	if err != nil {
		return err
	}

	var priv1, priv2 jwks
	if planExists {
		priv1, priv2 = existing.Client.JWKS, existing.Client2.JWKS
		if err := requireNonEmptyPrivateKey(priv1, planPath+": client"); err != nil {
			return err
		}
		if err := requireNonEmptyPrivateKey(priv2, planPath+": client2"); err != nil {
			return err
		}
	} else {
		// client1 is registered PS256/RSA directly (not ES256 plus a
		// separate third client, unlike baseline/message-signing/ciba) —
		// the suite's own ...-signature-algorithm-is-RS256-fails modules
		// only need the plan's first client already PS256-registered to
		// stop self-skipping; see oidf-config/README.md's own account of
		// switching this client from ES256 for exactly that reason.
		priv1, _, err = generatePS256Key(conformanceKeyLabelPrefix + "ciba-mtls-client1-rsa-key1")
		if err != nil {
			return fmt.Errorf("generate client1 key: %w", err)
		}
		priv2, _, err = generateKey("ciba-mtls-client2")
		if err != nil {
			return fmt.Errorf("generate client2 key: %w", err)
		}
	}
	pub1, pub2 := publicOnly(priv1), publicOnly(priv2)

	configPath := filepath.Join(dir, "ciba-mtls.config.json")
	clientIDs, err := patchCIBAMTLSConfig(configPath, pub1, pub2)
	if err != nil {
		return fmt.Errorf("update %s: %w", configPath, err)
	}

	if planExists {
		fmt.Printf("ciba-mtls: %s already exists — resynced %s's public keys to match it\n", planPath, configPath)
		return nil
	}

	// The suite's own mTLS-bound-token check for this profile never
	// pre-registers a certificate thumbprint anywhere in config.json
	// (sender_constrain=mtls binds dynamically to whatever certificate
	// is actually presented at token time) — unlike client-auth-mtls's
	// own certificate, this one has nothing to stay in sync with, so a
	// fresh certificate on every run is fine even when resyncing keys.
	mtlsCert, mtlsKey, err := generateMTLSCertKeyPEM(alias + mtlsSuiteClientCNSuffix)
	if err != nil {
		return fmt.Errorf("generate client1 mtls certificate: %w", err)
	}
	mtls2Cert, mtls2Key, err := generateMTLSCertKeyPEM(alias + mtlsSuiteClient2CNSuffix)
	if err != nil {
		return fmt.Errorf("generate client2 mtls certificate: %w", err)
	}

	cfg := cibaMTLSPlan{Alias: alias}
	cfg.Server.DiscoveryURL = issuerURL(issuerHost, wellKnownConfigPath)
	cfg.MTLS = mtlsBlock{Cert: mtlsCert, Key: mtlsKey}
	cfg.MTLS2 = mtlsBlock{Cert: mtls2Cert, Key: mtls2Key}
	cfg.Client = cibaMTLSClient{
		ClientID: clientIDs[0], Scope: fullScope, JWKS: priv1,
		HintType: "login_hint", HintValue: conformanceTestSubject,
	}
	cfg.Client2 = cibaMTLSClient2{
		ClientID: clientIDs[1], Scope: fullScope, JWKS: priv2,
		ACRValue: silverACR,
	}
	// Port 8444, not 8443: RFC 8705 sender-constraining means this
	// resource call must go over the mTLS listener itself — the plain
	// listener has no way to bind the access token to this connection's
	// certificate at all.
	cfg.Resource.ResourceURL = mtlsURL(issuerHost, userinfoPath)
	cfg.AutomatedCibaApprovalURL = issuerURL(issuerHost, backchannelApprovalPath) + cibaApprovalQuery

	out, err := marshalIndentNoEscape(cfg)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(planPath, out, 0o600); err != nil { // #nosec G306 -- mirrors writePlanConfig's own owner-only rationale (embeds priv1/priv2/mtlsKey/mtls2Key)
		return err
	}
	fmt.Printf("ciba-mtls: generated fresh client keys and certificates, wrote %s and updated %s\n", planPath, configPath)
	return nil
}

// clientAuthMTLSClient is this profile's own "client"/"client2" plan
// shape. RFC 8705 §2 mTLS client authentication carries no signed
// assertion, so this AS's own config.json never registers a jwks for
// either client here — but the suite's own plan config still needs one
// regardless of client_auth_type: ValidateClientJWKsPrivatePart runs
// unconditionally in this test module's own sequence and fails outright
// ("Couldn't find JWKS in configuration") without it, confirmed live —
// the initial version of this profile omitted jwks entirely (reasoning
// from GetStaticClientConfiguration alone, which really is unconditional
// on client_id only) and every browser-flow module INTERRUPTED on
// exactly this condition. This key is otherwise unused by either side.
type clientAuthMTLSClient struct {
	ClientID       string `json:"client_id"`
	Scope          string `json:"scope"`
	JWKS           jwks   `json:"jwks"`
	DPoPSigningAlg string `json:"dpop_signing_alg"`
}

// clientAuthMTLSPlan mirrors planConfig, minus the RS256-client-assertion
// override entry (meaningless here — this profile never builds a client
// assertion at all, so ensure-signed-client-assertion-with-RS256-fails
// doesn't apply), plus the same MTLS/MTLS2 cert blocks ciba-mtls
// already established: AbstractFAPI2SPFinalServerTestModule.configureClient
// requests them via the identical ExtractMTLSCertificatesFromConfiguration
// condition whenever ClientAuthType.MTLS is selected, not just when
// FAPI2SenderConstrainMethod.MTLS is (confirmed by disassembly).
type clientAuthMTLSPlan struct {
	Alias  string `json:"alias"`
	Server struct {
		DiscoveryURL string `json:"discoveryUrl"`
	} `json:"server"`
	MTLS     mtlsBlock            `json:"mtls"`
	MTLS2    mtlsBlock            `json:"mtls2"`
	Client   clientAuthMTLSClient `json:"client"`
	Client2  clientAuthMTLSClient `json:"client2"`
	Resource struct {
		ResourceURL string `json:"resourceUrl"`
	} `json:"resource"`
	Browser  []browserBlock           `json:"browser"`
	Override map[string]overrideEntry `json:"override"`
	Options  struct {
		BrowsercontrolCSSEnable bool `json:"browsercontrol_css_enable"`
	} `json:"options"`
}

// certPEMThumbprint parses a PEM-encoded certificate and returns its
// RFC 8705 §3.1 x5t#S256 thumbprint (internal/mtls.Thumbprint) — the
// same value this AS's own server/client_auth_mtls.go computes from a
// live TLS connection's peer certificate, so a client presenting
// certPEM's matching private key authenticates successfully once this
// value is registered as the client's expected_certificate_thumbprint.
func certPEMThumbprint(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	return mtls.Thumbprint(cert), nil
}

// patchClientAuthMTLSConfig writes thumb1/thumb2 into
// clients[0/1].expected_certificate_thumbprint in the committed
// client-auth-mtls.config.json, leaving every other field — id,
// redirect_uris, client_auth_method, allowed_scopes — exactly as
// already committed, the same preserve-what-this-tool-doesn't-own
// approach patchConformanceASConfig/patchCIBAMTLSConfig use.
func patchClientAuthMTLSConfig(path string, thumb1, thumb2 string) (clientIDs [2]string, err error) {
	top, clients, err := readConfigClients(path)
	if err != nil {
		return clientIDs, err
	}
	// At least 2, not exactly 2 — the same "trailing clients this
	// function doesn't own are safe to leave untouched" reasoning
	// patchCIBAMTLSConfig's own doc comment explains: on a fresh clone,
	// setupClientCredentialsGrantVariant has since grown
	// client-auth-mtls(-and-mtls).config.json to 4 entries (client1,
	// client2, and two client_credentials clients); this function only
	// ever reads/writes index 0 and 1.
	if len(clients) < 2 {
		return clientIDs, fmt.Errorf("expected at least 2 clients, found %d", len(clients))
	}

	thumbprints := [2]string{thumb1, thumb2}
	for i := range 2 {
		var id string
		if err := json.Unmarshal(clients[i]["id"], &id); err != nil {
			return clientIDs, fmt.Errorf("parse clients[%d].id: %w", i, err)
		}
		clientIDs[i] = id

		encoded, err := json.Marshal(thumbprints[i])
		if err != nil {
			return clientIDs, err
		}
		clients[i]["expected_certificate_thumbprint"] = encoded
	}

	encodedClients, err := marshalIndentNoEscape(clients)
	if err != nil {
		return clientIDs, err
	}
	top["clients"] = encodedClients

	out, err := marshalIndentNoEscape(top)
	if err != nil {
		return clientIDs, err
	}
	out = append(out, '\n')
	return clientIDs, os.WriteFile(path, out, 0o644) // #nosec G306 -- this AS's own config.json carries only a public thumbprint derived from the certificate, meant to be world-readable
}

// setupClientAuthMTLSVariant covers the RFC 8705 §2 client-authentication
// axis on a plain FAPI2SPFinal AS test plan run (rather than
// FAPI-CIBA-ID1) — client_auth_type=mtls, either sender_constrain=dpop
// (name="client-auth-mtls", senderConstrainMTLS=false — orthogonal to
// setupCIBAMTLS's §3 coverage, only the client's own authentication
// mechanism changes) or sender_constrain=mtls too
// (name="client-auth-mtls-and-mtls", senderConstrainMTLS=true — RFC
// 8705 §2 and §3 together on the same client, the one FAPI2SP register
// combination neither this profile alone nor the generic
// profile/writePlanConfig "mtls" entry covers). One certificate
// satisfies both axes when combined: storage.RegisteredClientConfig's
// ClientAuthMethod and SenderConstrain fields are already fully
// orthogonal, nothing library-side stops registering both on one
// client. Registers both clients storage.ClientAuthMethodSelfSignedTLSClientAuth
// — the suite's own ClientAuthType variant model has no separate
// self-signed vs. CA-issued distinction (confirmed by disassembly: just
// one MTLS value), so from the suite's perspective either of this AS's
// two mTLS client-authentication methods is an equally valid target;
// self-signed was chosen because it's what the suite's own
// generateMTLSCertKeyPEM-shaped certificate already is, with no need to
// additionally fabricate or reason about a subject DN.
func setupClientAuthMTLSVariant(dir, name string, senderConstrainMTLS bool) error {
	planPath := filepath.Join(dir, name+"-plan.json")
	alias := "gofapi-" + name
	issuerHost := "conformance-as-" + name

	existing, planExists, err := loadExistingPlan[clientAuthMTLSPlan](planPath)
	if err != nil {
		return err
	}

	// thumb1/thumb2 — derived from whichever certificate is actually in
	// play, existing or fresh — are the only thing that has to stay in
	// sync with config.json here: clientAuthMTLSClient.JWKS is a
	// structural-only key neither side ever checks (see that type's own
	// doc comment), so it's always safe to mint fresh even on resync.
	var cert1PEM, key1PEM, cert2PEM, key2PEM, thumb1, thumb2 string
	if planExists {
		cert1PEM, key1PEM = existing.MTLS.Cert, existing.MTLS.Key
		cert2PEM, key2PEM = existing.MTLS2.Cert, existing.MTLS2.Key
		if cert1PEM == "" || cert2PEM == "" {
			return fmt.Errorf("%s: missing mtls/mtls2 certificate blocks", planPath)
		}
	} else {
		cert1PEM, key1PEM, err = generateMTLSCertKeyPEM(alias + mtlsSuiteClientCNSuffix)
		if err != nil {
			return fmt.Errorf("generate client1 mtls certificate: %w", err)
		}
		cert2PEM, key2PEM, err = generateMTLSCertKeyPEM(alias + mtlsSuiteClient2CNSuffix)
		if err != nil {
			return fmt.Errorf("generate client2 mtls certificate: %w", err)
		}
	}
	thumb1, err = certPEMThumbprint(cert1PEM)
	if err != nil {
		return fmt.Errorf("thumbprint client1 certificate: %w", err)
	}
	thumb2, err = certPEMThumbprint(cert2PEM)
	if err != nil {
		return fmt.Errorf("thumbprint client2 certificate: %w", err)
	}

	configPath := filepath.Join(dir, name+".config.json")
	clientIDs, err := patchClientAuthMTLSConfig(configPath, thumb1, thumb2)
	if err != nil {
		return fmt.Errorf("update %s: %w", configPath, err)
	}

	if planExists {
		fmt.Printf("%s: %s already exists — resynced %s's certificate thumbprints to match it\n", name, planPath, configPath)
		return nil
	}

	priv1, _, err := generateKey(name + "-client1")
	if err != nil {
		return fmt.Errorf("generate client1 key: %w", err)
	}
	priv2, _, err := generateKey(name + "-client2")
	if err != nil {
		return fmt.Errorf("generate client2 key: %w", err)
	}

	authorizeURL := issuerURL(issuerHost, "/authorize*")
	trueVal := true
	one := 1
	consentTask := browserTask{
		Task: "Consent", Match: authorizeURL, Optional: &trueVal,
		Commands: [][]string{{"click", "xpath", "//button[@name='decision' and @value='approve']", "optional"}},
	}
	consentBlock := browserBlock{Match: authorizeURL, Tasks: []browserTask{consentTask}}

	cfg := clientAuthMTLSPlan{Alias: alias}
	cfg.Server.DiscoveryURL = issuerURL(issuerHost, wellKnownConfigPath)
	cfg.MTLS = mtlsBlock{Cert: cert1PEM, Key: key1PEM}
	cfg.MTLS2 = mtlsBlock{Cert: cert2PEM, Key: key2PEM}
	cfg.Client = clientAuthMTLSClient{ClientID: clientIDs[0], Scope: fullScope, JWKS: priv1, DPoPSigningAlg: "ES256"}
	cfg.Client2 = clientAuthMTLSClient{ClientID: clientIDs[1], Scope: fullScope, JWKS: priv2, DPoPSigningAlg: "ES256"}
	if senderConstrainMTLS {
		// mtlsURL, not issuerURL: this profile's access tokens are
		// mTLS-bound (sender_constrain=mtls), so the resource call must
		// go over the mTLS listener — see writePlanConfig's own
		// identical senderConstrainMTLS branch for the confirmed-live
		// reasoning.
		cfg.Resource.ResourceURL = mtlsURL(issuerHost, userinfoPath)
	} else {
		cfg.Resource.ResourceURL = issuerURL(issuerHost, userinfoPath)
	}
	cfg.Browser = []browserBlock{consentBlock}
	cfg.Override = baseOverrides(authorizeURL, consentBlock, &one)
	cfg.Options.BrowsercontrolCSSEnable = false

	out, err := marshalIndentNoEscape(cfg)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(planPath, out, 0o600); err != nil { // #nosec G306 -- mirrors writePlanConfig's own owner-only rationale (embeds the mtls certificate private keys)
		return err
	}
	fmt.Printf("%s: generated fresh certificates, wrote %s and updated %s\n", name, planPath, configPath)
	return nil
}

// cibaPingClient/cibaPingClient2 mirror cibaMTLSClient/cibaMTLSClient2
// exactly (client authentication stays private_key_jwt, unaffected by
// delivery mode) — hint_type/hint_value are not optional, confirmed
// live: omitting them entirely (this profile's first version) fails
// fapi-ciba-id1's own AddHintToAuthorizationEndpointRequest outright
// ("the 'hint_type' provided in the configuration must be one of
// 'login_hint_token', 'id_token_hint' or 'login_hint'"), the same
// requirement poll's own ciba-mtls profile already satisfies.
type cibaPingClient struct {
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	JWKS      jwks   `json:"jwks"`
	HintType  string `json:"hint_type"`
	HintValue string `json:"hint_value"`
}

type cibaPingClient2 struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	JWKS     jwks   `json:"jwks"`
	ACRValue string `json:"acr_value"`
}

type cibaPingPlan struct {
	Alias  string `json:"alias"`
	Server struct {
		DiscoveryURL string `json:"discoveryUrl"`
	} `json:"server"`
	MTLS     mtlsBlock       `json:"mtls"`
	MTLS2    mtlsBlock       `json:"mtls2"`
	Client   cibaPingClient  `json:"client"`
	Client2  cibaPingClient2 `json:"client2"`
	Resource struct {
		ResourceURL string `json:"resourceUrl"`
	} `json:"resource"`
	AutomatedCibaApprovalURL string `json:"automated_ciba_approval_url"`
}

// appendCIBAPingClients adds two new client entries to the committed
// ciba-mtls.config.json — alongside (not replacing) the two poll-mode
// clients setupCIBAMTLS already manages there — registered
// storage.BackchannelTokenDeliveryModePing, each with its own
// notification endpoint under a *different* suite plan alias
// ("gofapi-ciba-ping") than the poll-mode plan uses
// ("gofapi-ciba-mtls"): the notification endpoint URL a static,
// non-DCR client registers is fixed for the client's whole lifetime,
// so it can't be shared with a plan run using a different alias.
//
// pub1/pub2 are always this client's own current public keys —
// setupCIBAPing derives them either from a brand-new keypair (no
// existing ciba-ping-plan.json) or straight from that plan's own
// already-generated private key (see loadExistingPlan's own doc
// comment for why this must happen on every run, not just once). So
// when these two client IDs are already present here (from a previous
// run's commit of this same, non-gitignored config file), this must
// refresh their "jwks" in place to match — mirroring
// patchCIBAMTLSConfig's own always-overwrite approach — rather than
// leave the file alone: doing so would leave the server registered
// with a *stale* public key while the plan signs with a different
// private key, so every request this client makes fails client
// assertion verification (confirmed live:
// "invalid_client: client assertion verification failed" on the very
// first backchannel authentication request).
func appendCIBAPingClients(path string, pub1, pub2 jwks, notificationEndpoint1, notificationEndpoint2 string) (clientIDs [2]string, err error) {
	const clientID1 = conformanceKeyLabelPrefix + "ciba-ping-client-1"
	const clientID2 = conformanceKeyLabelPrefix + "ciba-ping-client-2"
	clientIDs = [2]string{clientID1, clientID2}

	top, clients, err := readConfigClients(path)
	if err != nil {
		return clientIDs, err
	}

	newJWKS := map[string]jwks{clientID1: pub1, clientID2: pub2}
	found := map[string]bool{}
	for i := range clients {
		var id string
		if err := json.Unmarshal(clients[i]["id"], &id); err != nil {
			return clientIDs, fmt.Errorf("parse clients[].id: %w", err)
		}
		pub, ok := newJWKS[id]
		if !ok {
			continue
		}
		encoded, err := json.Marshal(pub)
		if err != nil {
			return clientIDs, err
		}
		clients[i]["jwks"] = encoded
		found[id] = true
	}

	switch {
	case found[clientID1] && found[clientID2]:
		fmt.Printf("ciba-ping: clients already present in %s, refreshed jwks to match the freshly generated plan\n", path)
		return clientIDs, writeCIBAConfigClients(path, top, clients)
	case found[clientID1] || found[clientID2]:
		return clientIDs, fmt.Errorf("found only one of %q/%q in %s", clientID1, clientID2, path)
	}

	callback := "https://localhost.emobix.co.uk:8443/test/a/gofapi-ciba-ping/callback"
	newClients := []map[string]any{
		{
			// client1 is registered PS256/RSA, not ES256 — mirrors
			// setupCIBAMTLS's own identical fix: the suite's
			// ...-signature-algorithm-is-RS256-fails modules only start
			// running (rather than self-skipping) when the plan's first
			// client is already PS256-registered. Confirmed live: this
			// took AS ciba-ping from 3 unexpectedly-SKIPPED modules to a
			// clean run.
			"id": clientID1, "redirect_uris": []string{callback},
			"client_assertion_algorithm":                   "PS256",
			"backchannel_authentication_request_algorithm": "PS256",
			"allowed_scopes":                               []string{"openid", "accounts", "offline_access"},
			"jwks":                                         pub1,
			"sender_constrain":                             "mtls",
			"backchannel_token_delivery_mode":              "ping",
			"backchannel_client_notification_endpoint":     notificationEndpoint1,
		},
		{
			"id": clientID2, "redirect_uris": []string{callback},
			"client_assertion_algorithm":                   "ES256",
			"backchannel_authentication_request_algorithm": "ES256",
			"allowed_scopes":                               []string{"openid", "accounts", "offline_access"},
			"jwks":                                         pub2,
			"sender_constrain":                             "mtls",
			"backchannel_token_delivery_mode":              "ping",
			"backchannel_client_notification_endpoint":     notificationEndpoint2,
		},
	}
	for _, nc := range newClients {
		encoded, err := marshalIndentNoEscape(nc)
		if err != nil {
			return clientIDs, err
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &raw); err != nil {
			return clientIDs, err
		}
		clients = append(clients, raw)
	}

	return clientIDs, writeCIBAConfigClients(path, top, clients)
}

// writeCIBAConfigClients re-serializes top's "clients" array from
// clients and writes the result back to path — the common tail shared
// by appendCIBAPingClients' refresh-in-place and append-new-clients
// branches.
func writeCIBAConfigClients(path string, top map[string]json.RawMessage, clients []map[string]json.RawMessage) error {
	encodedClients, err := marshalIndentNoEscape(clients)
	if err != nil {
		return err
	}
	top["clients"] = encodedClients

	out, err := marshalIndentNoEscape(top)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644) // #nosec G306 -- this AS's own config.json carries only public keys, meant to be world-readable
}

// setupCIBAPing covers the CIBA §10.2 ping delivery mode, orthogonal to
// setupCIBAMTLS's own §3 sender-constraining coverage above: it adds two
// *additional* clients to the same committed ciba-mtls.config.json and
// the same running conformance-as-ciba-mtls container setupCIBAMTLS
// already configures — sender_constrain stays "mtls" (CIBA's own
// mTLS-bound-access-token requirement applies unconditionally,
// regardless of delivery mode; see oidf-config/README.md), only
// backchannel_token_delivery_mode changes. Runs under its own suite
// plan alias ("gofapi-ciba-ping") so this plan's notification endpoint
// doesn't collide with the poll-mode plan's — see
// appendCIBAPingClients's own doc comment. Idempotent the same way
// every other setup* function here is — see the package doc comment:
// never regenerates an existing ciba-ping-plan.json's own keys, but
// always resyncs ciba-mtls.config.json's public keys to match whatever
// it currently holds.
func setupCIBAPing(dir string) error {
	planPath := filepath.Join(dir, "ciba-ping-plan.json")
	const alias = "gofapi-ciba-ping"
	const issuerHost = "conformance-as-ciba-mtls" // same running container as setupCIBAMTLS

	existing, planExists, err := loadExistingPlan[cibaPingPlan](planPath)
	if err != nil {
		return err
	}

	var priv1JWKS, priv2JWKS jwks
	if planExists {
		priv1JWKS, priv2JWKS = existing.Client.JWKS, existing.Client2.JWKS
		if err := requireNonEmptyPrivateKey(priv1JWKS, planPath+": client"); err != nil {
			return err
		}
		if err := requireNonEmptyPrivateKey(priv2JWKS, planPath+": client2"); err != nil {
			return err
		}
	} else {
		priv1JWKS, _, err = generatePS256Key(conformanceKeyLabelPrefix + "ciba-ping-client1-rsa-key1")
		if err != nil {
			return fmt.Errorf("generate client1 key: %w", err)
		}
		priv2JWKS, _, err = generateKey("ciba-ping-client2")
		if err != nil {
			return fmt.Errorf("generate client2 key: %w", err)
		}
	}
	pub1, pub2 := publicOnly(priv1JWKS), publicOnly(priv2JWKS)

	notificationEndpoint := "https://localhost.emobix.co.uk:8443/test/a/" + alias + "/ciba-notification-endpoint"

	configPath := filepath.Join(dir, "ciba-mtls.config.json")
	clientIDs, err := appendCIBAPingClients(configPath, pub1, pub2, notificationEndpoint, notificationEndpoint)
	if err != nil {
		return fmt.Errorf("update %s: %w", configPath, err)
	}

	if planExists {
		return nil // appendCIBAPingClients already reported the resync above
	}

	// Same reasoning as setupCIBAMTLS's own identical comment: this
	// certificate is never pre-registered anywhere in config.json, so a
	// fresh one on every run is fine even when resyncing keys — but that
	// branch already returned above, so this only ever runs when
	// generating everything from scratch.
	mtlsCert, mtlsKey, err := generateMTLSCertKeyPEM(alias + mtlsSuiteClientCNSuffix)
	if err != nil {
		return fmt.Errorf("generate client1 mtls certificate: %w", err)
	}
	mtls2Cert, mtls2Key, err := generateMTLSCertKeyPEM(alias + mtlsSuiteClient2CNSuffix)
	if err != nil {
		return fmt.Errorf("generate client2 mtls certificate: %w", err)
	}

	cfg := cibaPingPlan{Alias: alias}
	cfg.Server.DiscoveryURL = issuerURL(issuerHost, wellKnownConfigPath)
	cfg.MTLS = mtlsBlock{Cert: mtlsCert, Key: mtlsKey}
	cfg.MTLS2 = mtlsBlock{Cert: mtls2Cert, Key: mtls2Key}
	cfg.Client = cibaPingClient{
		ClientID: clientIDs[0], Scope: fullScope, JWKS: priv1JWKS,
		HintType: "login_hint", HintValue: conformanceTestSubject,
	}
	cfg.Client2 = cibaPingClient2{
		ClientID: clientIDs[1], Scope: fullScope, JWKS: priv2JWKS,
		ACRValue: silverACR,
	}
	// Port 8444, not 8443: RFC 8705 sender-constraining means this
	// resource call must go over the mTLS listener itself — mirrors
	// setupCIBAMTLS's own identical reasoning.
	cfg.Resource.ResourceURL = mtlsURL(issuerHost, userinfoPath)
	cfg.AutomatedCibaApprovalURL = issuerURL(issuerHost, backchannelApprovalPath) + cibaApprovalQuery

	out, err := marshalIndentNoEscape(cfg)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(planPath, out, 0o600); err != nil { // #nosec G306 -- mirrors setupCIBAMTLS's own owner-only rationale (embeds client private keys and mtls certificate keys)
		return err
	}
	fmt.Printf("ciba-ping: generated fresh client keys and certificates, wrote %s and updated %s\n", planPath, configPath)
	return nil
}

// appendCIBAClientAuthMTLSClients adds two more client entries to the
// same committed ciba-mtls.config.json setupCIBAMTLS/appendCIBAPingClients
// already manage — the RFC 8705 §2 client-authentication counterpart to
// both: client_auth_method/expected_certificate_thumbprint replace
// jwks-based client_assertion_algorithm entirely (certificate-based
// client authentication carries no signed assertion to register an
// algorithm for), but jwks and backchannel_authentication_request_algorithm
// stay — FAPI-CIBA always requires a signed backchannel authentication
// *request* regardless of how the client authenticates itself (see
// server/backchannel_authentication.go's own doc comment), so these
// clients still need a request-object signing key of their own,
// entirely independent of the certificate that authenticates them.
// sender_constrain stays "mtls" (CIBA's own mTLS-bound-access-token
// requirement is unconditional, same as every other client already in
// this file). deliveryMode/notificationEndpoint1/notificationEndpoint2
// mirror appendCIBAPingClients' own optional ping-mode fields — pass ""
// for poll mode (the implicit default, matching clients[0]/[1]'s own
// shape in this same file), "ping" plus real endpoints otherwise.
func appendCIBAClientAuthMTLSClients(path, idSuffix string, pub1, pub2 jwks, thumb1, thumb2, deliveryMode, notificationEndpoint1, notificationEndpoint2 string) (clientIDs [2]string, err error) {
	clientID1 := conformanceKeyLabelPrefix + "ciba-" + idSuffix + "-client-1"
	clientID2 := conformanceKeyLabelPrefix + "ciba-" + idSuffix + "-client-2"
	clientIDs = [2]string{clientID1, clientID2}

	top, clients, err := readConfigClients(path)
	if err != nil {
		return clientIDs, err
	}

	newEntries := map[string]jwks{clientID1: pub1, clientID2: pub2}
	newThumbs := map[string]string{clientID1: thumb1, clientID2: thumb2}
	found := map[string]bool{}
	for i := range clients {
		var id string
		if err := json.Unmarshal(clients[i]["id"], &id); err != nil {
			return clientIDs, fmt.Errorf("parse clients[].id: %w", err)
		}
		pub, ok := newEntries[id]
		if !ok {
			continue
		}
		encodedJWKS, err := json.Marshal(pub)
		if err != nil {
			return clientIDs, err
		}
		encodedThumb, err := json.Marshal(newThumbs[id])
		if err != nil {
			return clientIDs, err
		}
		clients[i]["jwks"] = encodedJWKS
		clients[i]["expected_certificate_thumbprint"] = encodedThumb
		found[id] = true
	}

	switch {
	case found[clientID1] && found[clientID2]:
		fmt.Printf("ciba-%s: clients already present in %s, refreshed jwks/thumbprint to match the freshly generated plan\n", idSuffix, path)
		return clientIDs, writeCIBAConfigClients(path, top, clients)
	case found[clientID1] || found[clientID2]:
		return clientIDs, fmt.Errorf("found only one of %q/%q in %s", clientID1, clientID2, path)
	}

	callback := "https://localhost.emobix.co.uk:8443/test/a/gofapi-ciba-" + idSuffix + "/callback"
	newClients := []map[string]any{
		{
			// client1 stays PS256/RSA for backchannel_authentication_request_algorithm
			// — mirrors setupCIBAMTLS/appendCIBAPingClients' own identical
			// reasoning for why an RS256-signed-request negative test module
			// needs the plan's first client already PS256-registered to run
			// at all rather than self-skip.
			"id": clientID1, "redirect_uris": []string{callback},
			"backchannel_authentication_request_algorithm": "PS256",
			"allowed_scopes":                  []string{"openid", "accounts", "offline_access"},
			"jwks":                            pub1,
			"client_auth_method":              "self_signed_tls_client_auth",
			"expected_certificate_thumbprint": thumb1,
			"sender_constrain":                "mtls",
		},
		{
			"id": clientID2, "redirect_uris": []string{callback},
			"backchannel_authentication_request_algorithm": "ES256",
			"allowed_scopes":                  []string{"openid", "accounts", "offline_access"},
			"jwks":                            pub2,
			"client_auth_method":              "self_signed_tls_client_auth",
			"expected_certificate_thumbprint": thumb2,
			"sender_constrain":                "mtls",
		},
	}
	if deliveryMode != "" {
		newClients[0]["backchannel_token_delivery_mode"] = deliveryMode
		newClients[0]["backchannel_client_notification_endpoint"] = notificationEndpoint1
		newClients[1]["backchannel_token_delivery_mode"] = deliveryMode
		newClients[1]["backchannel_client_notification_endpoint"] = notificationEndpoint2
	}
	for _, nc := range newClients {
		encoded, err := marshalIndentNoEscape(nc)
		if err != nil {
			return clientIDs, err
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &raw); err != nil {
			return clientIDs, err
		}
		clients = append(clients, raw)
	}

	return clientIDs, writeCIBAConfigClients(path, top, clients)
}

// setupCIBAClientAuthMTLSVariant covers both FAPI-CIBA OP register
// profiles "Poll w/ MTLS" (suffix="client-auth-mtls",
// deliveryMode="", the implicit poll default) and "Ping w/ MTLS"
// (suffix="ping-client-auth-mtls", deliveryMode="ping") — RFC 8705 §2
// client authentication for the backchannel authentication endpoint,
// orthogonal to every other CIBA profile here (all private_key_jwt so
// far). Adds two more clients to the same committed
// ciba-mtls.config.json and the same running conformance-as-ciba-mtls
// container setupCIBAMTLS already configures, under their own suite
// plan alias so registrations don't collide with the private_key_jwt
// plans'. Idempotent the same way every other setup* function here is —
// see the package doc comment.
func setupCIBAClientAuthMTLSVariant(dir, suffix, deliveryMode string) error {
	name := "ciba-" + suffix
	planPath := filepath.Join(dir, name+"-plan.json")
	alias := "gofapi-" + name
	const issuerHost = "conformance-as-ciba-mtls" // same running container as setupCIBAMTLS

	existing, planExists, err := loadExistingPlan[cibaMTLSPlan](planPath)
	if err != nil {
		return err
	}

	// Both the jwks (the backchannel authentication *request*'s own
	// signing key — required regardless of client-authentication method,
	// see appendCIBAClientAuthMTLSClients' own doc comment) and the
	// certificate thumbprint (this profile's actual client-authentication
	// credential) matter here, unlike setupClientAuthMTLSVariant's
	// throwaway jwks — both must come from the existing plan on resync.
	var priv1JWKS, priv2JWKS jwks
	var mtlsCert, mtlsKey, mtls2Cert, mtls2Key string
	if planExists {
		priv1JWKS, priv2JWKS = existing.Client.JWKS, existing.Client2.JWKS
		mtlsCert, mtlsKey = existing.MTLS.Cert, existing.MTLS.Key
		mtls2Cert, mtls2Key = existing.MTLS2.Cert, existing.MTLS2.Key
		if err := requireNonEmptyPrivateKey(priv1JWKS, planPath+": client"); err != nil {
			return err
		}
		if err := requireNonEmptyPrivateKey(priv2JWKS, planPath+": client2"); err != nil {
			return err
		}
		if mtlsCert == "" || mtls2Cert == "" {
			return fmt.Errorf("%s: missing mtls/mtls2 certificate blocks", planPath)
		}
	} else {
		priv1JWKS, _, err = generatePS256Key(conformanceKeyLabelPrefix + name + "-client1-rsa-key1")
		if err != nil {
			return fmt.Errorf("generate client1 key: %w", err)
		}
		priv2JWKS, _, err = generateKey(name + "-client2")
		if err != nil {
			return fmt.Errorf("generate client2 key: %w", err)
		}
		mtlsCert, mtlsKey, err = generateMTLSCertKeyPEM(alias + mtlsSuiteClientCNSuffix)
		if err != nil {
			return fmt.Errorf("generate client1 mtls certificate: %w", err)
		}
		mtls2Cert, mtls2Key, err = generateMTLSCertKeyPEM(alias + mtlsSuiteClient2CNSuffix)
		if err != nil {
			return fmt.Errorf("generate client2 mtls certificate: %w", err)
		}
	}
	pub1, pub2 := publicOnly(priv1JWKS), publicOnly(priv2JWKS)
	thumb1, err := certPEMThumbprint(mtlsCert)
	if err != nil {
		return fmt.Errorf("thumbprint client1 certificate: %w", err)
	}
	thumb2, err := certPEMThumbprint(mtls2Cert)
	if err != nil {
		return fmt.Errorf("thumbprint client2 certificate: %w", err)
	}

	var notification1, notification2 string
	if deliveryMode != "" {
		notification1 = "https://localhost.emobix.co.uk:8443/test/a/" + alias + "/ciba-notification-endpoint"
		notification2 = notification1
	}

	configPath := filepath.Join(dir, "ciba-mtls.config.json")
	clientIDs, err := appendCIBAClientAuthMTLSClients(configPath, suffix, pub1, pub2, thumb1, thumb2, deliveryMode, notification1, notification2)
	if err != nil {
		return fmt.Errorf("update %s: %w", configPath, err)
	}

	if planExists {
		return nil // appendCIBAClientAuthMTLSClients already reported the resync above
	}

	cfg := cibaMTLSPlan{Alias: alias}
	cfg.Server.DiscoveryURL = issuerURL(issuerHost, wellKnownConfigPath)
	cfg.MTLS = mtlsBlock{Cert: mtlsCert, Key: mtlsKey}
	cfg.MTLS2 = mtlsBlock{Cert: mtls2Cert, Key: mtls2Key}
	cfg.Client = cibaMTLSClient{
		ClientID: clientIDs[0], Scope: fullScope, JWKS: priv1JWKS,
		HintType: "login_hint", HintValue: conformanceTestSubject,
	}
	cfg.Client2 = cibaMTLSClient2{
		ClientID: clientIDs[1], Scope: fullScope, JWKS: priv2JWKS,
		ACRValue: silverACR,
	}
	cfg.Resource.ResourceURL = mtlsURL(issuerHost, userinfoPath)
	cfg.AutomatedCibaApprovalURL = issuerURL(issuerHost, backchannelApprovalPath) + cibaApprovalQuery

	out, err := marshalIndentNoEscape(cfg)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(planPath, out, 0o600); err != nil { // #nosec G306 -- mirrors setupCIBAMTLS's own owner-only rationale (embeds client private keys and mtls certificate keys)
		return err
	}
	fmt.Printf("%s: generated fresh client keys and certificates, wrote %s and updated %s\n", name, planPath, configPath)
	return nil
}

// clientCredentialsGrantContainers is every already-running AS
// container the four FAPI2 Client Credentials Grant register profiles
// (MTLS+MTLS, MTLS+DPoP, private key+MTLS, private key+DPoP) reuse — no
// new docker-compose service needed, since RFC 6749 §4.4 has no browser
// hop at all and arrives at the same token endpoint every other grant
// already uses. baseName matches the existing *.config.json/container
// name exactly.
var clientCredentialsGrantContainers = []struct {
	baseName            string
	clientAuthMTLS      bool
	senderConstrainMTLS bool
}{
	{baseName: "baseline"},
	{baseName: "mtls", senderConstrainMTLS: true},
	{baseName: "client-auth-mtls", clientAuthMTLS: true},
	{baseName: "client-auth-mtls-and-mtls", clientAuthMTLS: true, senderConstrainMTLS: true},
}

// setupClientCredentialsGrantVariant adds one more client to the
// already-committed {baseName}.config.json and generates
// {baseName}-client-credentials-plan.json against the same already
// -running conformance-as-{baseName} container — no PAR, no
// authorize/redirect_uri/browser step, no ID token, no refresh token:
// RFC 6749 §4.4 is a direct client-to-token-endpoint exchange, the same
// reasoning RequestClientCredentialsToken's own doc comment
// (server/client_credentials.go) gives for why this needs none of the
// authorization_code-shaped plumbing every other profile here does.
// Reuses whichever axis this container already established
// (clientAuthMTLS mirrors setupClientAuthMTLSVariant's own certificate
// generation; !clientAuthMTLS mirrors the generic profile/writePlanConfig
// machinery's own jwks generation) rather than introducing a third
// client-shape convention.
// clientCredentialsGrantMaterial is the per-client key/certificate
// material clientCredentialsGrantEntries needs to build one client's
// config.json/plan.json entries — either freshly generated
// (generateClientCredentialsGrantMaterial) or recovered from an
// already-existing plan (setupClientCredentialsGrantVariant's own
// resync path), so both paths produce byte-for-byte identical entries
// for the same underlying material.
type clientCredentialsGrantMaterial struct {
	priv, pub       jwks
	certPEM, keyPEM string
}

// generateClientCredentialsGrantMaterial mints fresh key/certificate
// material for one client — needsCert mirrors clientAuthMTLS ||
// senderConstrainMTLS at the call site (one certificate covers both
// axes when combined, the same one-certificate precedent
// setupClientAuthMTLSVariant's own "MTLS + MTLS" case already
// established).
func generateClientCredentialsGrantMaterial(keyLabel, certCNSuffix string, needsCert, forceRSA bool) (m clientCredentialsGrantMaterial, err error) {
	if needsCert {
		m.certPEM, m.keyPEM, err = generateMTLSCertKeyPEM(certCNSuffix)
		if err != nil {
			return m, fmt.Errorf("generate client mtls certificate: %w", err)
		}
	}
	if forceRSA {
		m.priv, m.pub, err = generatePS256Key(keyLabel + "-rsa-key1")
	} else {
		m.priv, m.pub, err = generateKey(keyLabel)
	}
	if err != nil {
		return m, fmt.Errorf("generate client key: %w", err)
	}
	return m, nil
}

// clientCredentialsGrantEntries builds one client's config.json entry
// and plan "client"/"client2" entry from already-known material m —
// client1 PS256/RSA under !clientAuthMTLS (mirrors
// setupCIBAMTLS/appendCIBAPingClients' own identical reasoning: the
// plan's fapi2-security-profile-final-ensure-signed-client-assertion
// -with-RS256-fails module, present in every private_key_jwt combo's
// own module list, only starts running rather than self-skipping once
// the plan's first client is already PS256-registered), client2 (and
// both clients under clientAuthMTLS, which has no client_assertion
// /algorithm concept at all) plain ES256. The entry-shaping half of
// what a single clientCredentialsGrantClient call used to do in one
// step, split out so setupClientCredentialsGrantVariant's resync path
// can reuse it against material recovered from an existing plan
// instead of freshly generated material.
func clientCredentialsGrantEntries(clientID string, m clientCredentialsGrantMaterial, clientAuthMTLS, senderConstrainMTLS, forceRSA bool) (configEntry, planEntry map[string]any, err error) {
	configEntry = map[string]any{
		"id": clientID,
		// Structurally required by storage.NewRegisteredClient (every
		// client needs at least one redirect URI) even though this
		// grant never redirects anywhere — see that constructor's own
		// unconditional check.
		"redirect_uris":                   []string{"https://localhost.emobix.co.uk:8443/test/a/" + clientID + "/callback"},
		"allowed_scopes":                  []string{"accounts"},
		"allows_client_credentials_grant": true,
	}
	planEntry = map[string]any{
		"client_id": clientID,
		"scope":     "accounts",
	}
	if senderConstrainMTLS {
		configEntry["sender_constrain"] = "mtls"
	}
	if clientAuthMTLS {
		thumb, err := certPEMThumbprint(m.certPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("thumbprint client certificate: %w", err)
		}
		configEntry["client_auth_method"] = "self_signed_tls_client_auth"
		configEntry["expected_certificate_thumbprint"] = thumb
	}
	// The suite's own plan config needs a "jwks" entry regardless of
	// client_auth_type — ValidateClientJWKsPrivatePart runs
	// unconditionally (confirmed live: every clientAuthMTLS module
	// otherwise INTERRUPTED with "Couldn't find JWKS in configuration"),
	// the same quirk setupClientAuthMTLSVariant's own doc comment
	// already documents. This AS's own registration only needs the
	// public half when it's actually the client's authentication
	// mechanism (!clientAuthMTLS) — under clientAuthMTLS the
	// certificate alone authenticates the client, so the config-side
	// jwks/client_assertion_algorithm fields would go unused.
	planEntry["jwks"] = m.priv
	if !clientAuthMTLS {
		if forceRSA {
			configEntry["client_assertion_algorithm"] = "PS256"
		} else {
			configEntry["client_assertion_algorithm"] = "ES256"
		}
		configEntry["jwks"] = m.pub
	}
	return configEntry, planEntry, nil
}

// clientCredentialsPlanKeys is the minimal shape
// setupClientCredentialsGrantVariant needs to read back out of its own
// already-written plan.json — that plan is otherwise built as a plain
// map[string]any (see its own construction below), not a dedicated
// struct, since nothing else in this file needs to round-trip it.
type clientCredentialsPlanKeys struct {
	Client struct {
		JWKS jwks `json:"jwks"`
	} `json:"client"`
	Client2 struct {
		JWKS jwks `json:"jwks"`
	} `json:"client2"`
	MTLS  *mtlsBlock `json:"mtls,omitempty"`
	MTLS2 *mtlsBlock `json:"mtls2,omitempty"`
}

// setupClientCredentialsGrantVariant adds two more clients (client1,
// client2 — every fapi2-security-profile-final-test-plan variant
// structurally requires both, confirmed live: GetStaticClient2Configuration
// interrupts every module outright with "Definition for client2 not
// present in supplied configuration" otherwise, regardless of
// fapi_profile) to the already-committed {baseName}.config.json and
// generates {baseName}-client-credentials-plan.json against the same
// already-running conformance-as-{baseName} container — no PAR, no
// authorize/redirect_uri/browser step, no ID token, no refresh token:
// RFC 6749 §4.4 is a direct client-to-token-endpoint exchange, the same
// reasoning RequestClientCredentialsToken's own doc comment
// (server/client_credentials.go) gives for why this needs none of the
// authorization_code-shaped plumbing every other profile here does —
// only client1 is ever actually used to request a token; client2 is a
// structural-only registration, present but never exercised by any
// module in this profile's own live-confirmed module list.
func setupClientCredentialsGrantVariant(dir, baseName string, clientAuthMTLS, senderConstrainMTLS bool) error {
	name := baseName + "-client-credentials"
	planPath := filepath.Join(dir, name+"-plan.json")
	alias := "gofapi-" + name
	issuerHost := "conformance-as-" + baseName
	clientID1 := conformanceKeyLabelPrefix + name + "-client-1"
	clientID2 := conformanceKeyLabelPrefix + name + "-client-2"
	needsCert := clientAuthMTLS || senderConstrainMTLS

	existing, planExists, err := loadExistingPlan[clientCredentialsPlanKeys](planPath)
	if err != nil {
		return err
	}

	var m1, m2 clientCredentialsGrantMaterial
	if planExists {
		m1 = clientCredentialsGrantMaterial{priv: existing.Client.JWKS, pub: publicOnly(existing.Client.JWKS)}
		m2 = clientCredentialsGrantMaterial{priv: existing.Client2.JWKS, pub: publicOnly(existing.Client2.JWKS)}
		if err := requireNonEmptyPrivateKey(m1.priv, planPath+": client"); err != nil {
			return err
		}
		if err := requireNonEmptyPrivateKey(m2.priv, planPath+": client2"); err != nil {
			return err
		}
		if needsCert {
			if existing.MTLS == nil || existing.MTLS2 == nil {
				return fmt.Errorf("%s: missing mtls/mtls2 certificate blocks", planPath)
			}
			m1.certPEM, m1.keyPEM = existing.MTLS.Cert, existing.MTLS.Key
			m2.certPEM, m2.keyPEM = existing.MTLS2.Cert, existing.MTLS2.Key
		}
	} else {
		m1, err = generateClientCredentialsGrantMaterial(name+"-client1", alias+mtlsSuiteClientCNSuffix, needsCert, true)
		if err != nil {
			return err
		}
		m2, err = generateClientCredentialsGrantMaterial(name+"-client2", alias+mtlsSuiteClient2CNSuffix, needsCert, false)
		if err != nil {
			return err
		}
	}

	configEntry1, planEntry1, err := clientCredentialsGrantEntries(clientID1, m1, clientAuthMTLS, senderConstrainMTLS, true)
	if err != nil {
		return err
	}
	configEntry2, planEntry2, err := clientCredentialsGrantEntries(clientID2, m2, clientAuthMTLS, senderConstrainMTLS, false)
	if err != nil {
		return err
	}

	configPath := filepath.Join(dir, baseName+".config.json")
	top, clients, err := readConfigClients(configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	// Refresh these two client IDs' entries in place if config.json
	// already has them (mirroring appendCIBAPingClients' own
	// always-overwrite approach), rather than leaving a mismatched
	// config.json alone — the resync this whole file now performs on
	// every run, not just a one-time fresh-clone bootstrap.
	newEntries := map[string]map[string]any{clientID1: configEntry1, clientID2: configEntry2}
	found := map[string]bool{}
	for i, c := range clients {
		var id string
		if err := json.Unmarshal(c["id"], &id); err != nil {
			return fmt.Errorf("parse clients[].id: %w", err)
		}
		entry, ok := newEntries[id]
		if !ok {
			continue
		}
		encoded, err := marshalIndentNoEscape(entry)
		if err != nil {
			return err
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &raw); err != nil {
			return err
		}
		clients[i] = raw
		found[id] = true
	}
	switch {
	case found[clientID1] && found[clientID2]:
		fmt.Printf("%s: clients already present in %s, refreshed to match %s\n", name, configPath, planPath)
	case found[clientID1] || found[clientID2]:
		return fmt.Errorf("found only one of %q/%q in %s", clientID1, clientID2, configPath)
	default:
		for _, entry := range []map[string]any{configEntry1, configEntry2} {
			encoded, err := marshalIndentNoEscape(entry)
			if err != nil {
				return err
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &raw); err != nil {
				return err
			}
			clients = append(clients, raw)
		}
	}
	if err := writeCIBAConfigClients(configPath, top, clients); err != nil {
		return fmt.Errorf("update %s: %w", configPath, err)
	}

	if planExists {
		fmt.Printf("%s: %s already exists — resynced %s to match it\n", name, planPath, configPath)
		return nil
	}

	// accountsPath, not userinfoPath: see that constant's own doc
	// comment for why this profile alone needs the non-OIDC resource
	// endpoint.
	resourceURL := issuerURL(issuerHost, accountsPath)
	if senderConstrainMTLS {
		// mTLS-bound access tokens' resource call must go over the mTLS
		// listener — see writePlanConfig's own identical
		// senderConstrainMTLS branch for the confirmed-live reasoning.
		resourceURL = mtlsURL(issuerHost, accountsPath)
	}
	plan := map[string]any{
		"alias": alias,
		"server": map[string]any{
			"discoveryUrl": issuerURL(issuerHost, wellKnownConfigPath),
		},
		"client":   planEntry1,
		"client2":  planEntry2,
		"resource": map[string]any{"resourceUrl": resourceURL},
	}
	if needsCert {
		plan["mtls"] = mtlsBlock{Cert: m1.certPEM, Key: m1.keyPEM}
		plan["mtls2"] = mtlsBlock{Cert: m2.certPEM, Key: m2.keyPEM}
	}

	out, err := marshalIndentNoEscape(plan)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(planPath, out, 0o600); err != nil { // #nosec G306 -- embeds each client's own private key/mtls certificate key
		return err
	}
	fmt.Printf("%s: generated fresh client credentials, wrote %s and updated %s\n", name, planPath, configPath)
	return nil
}
