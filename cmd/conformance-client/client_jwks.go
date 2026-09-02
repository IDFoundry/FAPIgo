// This file adds -issuer mode's fixed-client-JWKS loading — the
// capability explicitly scoped out when fixed-identity mode was first
// built (see fixed_identity.go's own package doc comment): a plan
// registered on the hosted suite with private_key_jwt client
// authentication needs the client assertion signed by the exact same
// key every run, matching whatever public JWK was handed to the suite
// through its own guided UI at plan-creation time — an ephemeral,
// freshly-generated-per-run key (this driver's own long-standing
// default, still used everywhere -client-jwks isn't given) would never
// verify against a registration the suite already has on file.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

type clientJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

type clientJWKS struct {
	Keys []clientJWK `json:"keys"`
}

// loadClientAuthenticationSigner reads path (a JWK Set JSON file — see
// this driver's own gen-rp-pkjwt-mtls.go-style generator scripts) and
// returns the private signing key and kid of the first P-256 EC key it
// contains. This driver's own ClientAuthentication purpose only ever
// signs ES256 (main.go's purposes map hardcodes fapi.ES256 for it
// identically on the ephemeral path), so a P-256 EC key is the only
// shape this needs to support; a suite-registered client JWKS only
// ever needs one signing key, so the first (and normally only) P-256
// entry found is used.
func loadClientAuthenticationSigner(path string) (*ecdsa.PrivateKey, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read client jwks file: %w", err)
	}
	var set clientJWKS
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, "", fmt.Errorf("parse client jwks file: %w", err)
	}
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		if k.D == "" {
			return nil, "", fmt.Errorf("client jwks file: key %q has no private component (\"d\") — "+
				"this must be the client's PRIVATE key, not the public one handed to the suite", k.Kid)
		}
		x, err := decodeJWKCoordinate(k.X)
		if err != nil {
			return nil, "", fmt.Errorf("client jwks file: key %q: decode x: %w", k.Kid, err)
		}
		y, err := decodeJWKCoordinate(k.Y)
		if err != nil {
			return nil, "", fmt.Errorf("client jwks file: key %q: decode y: %w", k.Kid, err)
		}
		d, err := decodeJWKCoordinate(k.D)
		if err != nil {
			return nil, "", fmt.Errorf("client jwks file: key %q: decode d: %w", k.Kid, err)
		}
		priv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
			D:         d,
		}
		return priv, k.Kid, nil
	}
	return nil, "", fmt.Errorf("client jwks file %s: no P-256 EC private key found", path)
}

func decodeJWKCoordinate(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// buildFixedClientKeyManager builds a keys.KeyManager where
// keys.ClientAuthentication signs with the fixed private key loaded
// from jwksFile (loadClientAuthenticationSigner) — the key the suite
// already has the matching public half of, from plan registration —
// and every other purpose in purposes gets a fresh ephemeral key,
// exactly like ephemeral.NewKeyManager would generate for it. Those
// other purposes (DPoP proof signing, an optional signed request
// object) don't need to match anything the suite has on file the way a
// private_key_jwt client assertion key does — DPoP presents its own
// public key inline on every proof (RFC 9449 §4.2), and a signed
// request object's key comes from the same client JWKS this driver
// isn't yet fixing beyond ClientAuthentication.
func buildFixedClientKeyManager(jwksFile string, purposes map[keys.SigningPurpose]fapi.SignatureAlgorithm) (keys.KeyManager, error) {
	if _, ok := purposes[keys.ClientAuthentication]; !ok {
		return nil, fmt.Errorf("-client-jwks given but this run has no client-assertion signing purpose " +
			"(client_auth_type=mtls needs no signed assertion — drop -client-jwks, or drop -client-auth-mtls)")
	}
	fixedSigner, kid, err := loadClientAuthenticationSigner(jwksFile)
	if err != nil {
		return nil, err
	}

	signers := make(map[keys.SigningPurpose]crypto.Signer, len(purposes))
	algorithms := make(map[keys.SigningPurpose]fapi.SignatureAlgorithm, len(purposes))
	kids := make(map[keys.SigningPurpose]string, len(purposes))
	for purpose, alg := range purposes {
		algorithms[purpose] = alg
		if purpose == keys.ClientAuthentication {
			signers[purpose] = fixedSigner
			kids[purpose] = kid
			continue
		}
		signer, err := generateEphemeralSigner(alg)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key for purpose %v: %w", purpose, err)
		}
		signers[purpose] = signer
	}
	return keys.NewKeyManagerFromSigners(signers, algorithms, kids)
}

// generateEphemeralSigner mirrors keys/ephemeral's own unexported
// generateSigner — duplicated rather than exported from there, since
// it's an internal implementation detail of a different package this
// one has no other reason to depend on beyond this one helper.
func generateEphemeralSigner(alg fapi.SignatureAlgorithm) (crypto.Signer, error) {
	switch alg {
	case fapi.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case fapi.PS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	case fapi.EdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported algorithm %v for ephemeral signer", alg)
	}
}
