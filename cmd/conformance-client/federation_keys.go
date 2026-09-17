// This file adds -profile=federation's own private-key generation —
// unlike every other purpose this driver's keys ever serve (always kept
// behind a keys.KeyManager, never marshaled with their own private
// component — see client_jwks.go's own loadFixedClientSigner, which
// only ever *reads* one), the suite itself needs to sign as the mock OP
// and Trust Anchor this plan's config describes, using key material
// *we* choose and hand it directly (see federation.go's own package doc
// comment for why: the suite has no live discovery/fetch expectation on
// this side of the flow to have generated its own key material from).
// This is a deliberate, narrow exception to that "no private JWK ever
// leaves a KeyManager" precedent, scoped to plan-configuration payloads
// only, never returned to the suite over an authenticated channel.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// generateFederationJWK generates a fresh P-256 ES256 signing key and
// returns it both as a private clientJWKS (client_jwks.go's own
// reader-side type, reused here since the "kty"/"crv"/"kid"/"x"/"y"/"d"
// shape is identical either direction) — for embedding directly in a
// plan config field the suite expects to sign with — and the raw
// *ecdsa.PrivateKey, for anything this driver itself needs to sign with
// the same key (its own federation Entity Configuration, in
// particular).
func generateFederationJWK(kid string) (*ecdsa.PrivateKey, clientJWKS, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, clientJWKS{}, fmt.Errorf("generate key: %w", err)
	}
	coordSize := (priv.Curve.Params().BitSize + 7) / 8
	jwk := clientJWK{
		// No "use" tag: the suite's own LoadServerJWKs (op_server_jwks'
		// own path) only treats a key as an encryption-key candidate
		// when "use" is either absent or "enc" — a "sig"-tagged key
		// here left server_encryption_keys unpopulated entirely,
		// NPEing a later step that reads it unconditionally (confirmed
		// live). Every use of these keys elsewhere is signing-only
		// regardless.
		Kty: "EC", Crv: "P-256", Kid: kid, Alg: "ES256",
		X: base64.RawURLEncoding.EncodeToString(leftPad(priv.X.Bytes(), coordSize)),
		Y: base64.RawURLEncoding.EncodeToString(leftPad(priv.Y.Bytes(), coordSize)),
		D: base64.RawURLEncoding.EncodeToString(leftPad(priv.D.Bytes(), coordSize)),
	}
	return priv, clientJWKS{Keys: []clientJWK{jwk}}, nil
}

// publicJWKS strips "d" from every key in set — the shape a plan
// config field wants when it's describing keys purely for the suite's
// own *verification* use (this plan has none of those today — every
// federation.*_jwks field the suite reads is a signing key it uses
// itself — but kept alongside generateFederationJWK as this package's
// one place that already knows this encoding, should that change).
func publicJWKS(set clientJWKS) clientJWKS {
	out := clientJWKS{Keys: make([]clientJWK, len(set.Keys))}
	for i, k := range set.Keys {
		out.Keys[i] = clientJWK{Kty: k.Kty, Crv: k.Crv, Kid: k.Kid, X: k.X, Y: k.Y, Alg: k.Alg, Use: k.Use}
	}
	return out
}

// leftPad returns b left-padded with zero bytes to exactly size bytes —
// big.Int.Bytes() drops leading zero bytes, but a JWK EC coordinate
// (RFC 7518 §6.2.1.2/6.2.1.3) must be encoded at the curve's own fixed
// coordinate size (32 bytes for P-256) regardless of the integer's own
// value.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
