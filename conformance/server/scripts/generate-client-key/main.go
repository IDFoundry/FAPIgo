// Command generate-client-key produces one throwaway ES256 keypair for
// the OIDF conformance suite's test client to authenticate with
// (private_key_jwt client assertions, DPoP proofs, and — under the
// message-signing profile — signed request objects).
//
// It deliberately does not use this module's internal/jose package:
// that package is intentionally private (see ARCHITECTURE.md "No public
// JOSE utility package") and has no private-key JWK export, since a
// production role never needs to hand out a private key. This script is
// throwaway conformance-run tooling, not library code, so it hand-rolls
// the handful of JWK fields it needs instead.
//
// Usage:
//
//	go run ./conformance/server/scripts/generate-client-key [label]
//
// label defaults to "client" — pass "client2" when a test plan needs a
// second registered client (e.g. FAPI2SPFinal's multi-client modules)
// so the two keys' "kid" values don't collide when pasted side by side.
//
// Paste the "private JWK (suite config)" output into the OIDF
// conformance suite's plan config's client.jwks (or client2.jwks)
// field (it signs with the private key), and the "public JWK
// (conformance-as config)" output into this repo's conformance-as
// config file's clients[].jwks field (it only ever needs to verify).
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
)

func main() {
	label := "client"
	if len(os.Args) > 1 {
		label = os.Args[1]
	}
	kid := "gofapi-conformance-" + label + "-1"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	x := b64(priv.X.FillBytes(make([]byte, 32)))
	y := b64(priv.Y.FillBytes(make([]byte, 32)))
	d := b64(priv.D.FillBytes(make([]byte, 32)))

	privateJWK := map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
		"x": x, "y": y, "d": d,
	}
	publicJWK := map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
		"x": x, "y": y,
	}

	fmt.Println("=== private JWK (suite config: client.jwks) ===")
	printJSON(map[string]any{"keys": []any{privateJWK}})

	fmt.Println()
	fmt.Println("=== public JWK (conformance-as config: clients[].jwks) ===")
	printJSON(map[string]any{"keys": []any{publicJWK}})
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encode: %v", err)
	}
}
