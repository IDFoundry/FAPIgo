package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
)

// These tests cover one relying party using two authorization servers,
// A and B, where A (or whoever holds A's signing key) tries to have
// something it signed accepted by the Client configured for B. Both
// servers publish their key under the same "kid", and B's client is
// registered at both under the same client_id, so neither the kid nor
// the audience tells the two apart: only B's own keys and B's issuer
// do.

const (
	sharedKeysIssuerA = "https://op-a.example.com"
	sharedKeysIssuerB = "https://op-b.example.com"
	sharedKeysKeyID   = "k1"
)

// sharedKeysOP is one authorization server: its signing key, and a
// TLS server publishing it as its JWKS.
type sharedKeysOP struct {
	key  *ecdsa.PrivateKey
	jwks *httptest.Server
}

func newSharedKeysOP(t *testing.T) sharedKeysOP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))
	body := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q,"alg":"ES256","use":"sig"}]}`, x, y, sharedKeysKeyID)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return sharedKeysOP{key: key, jwks: ts}
}

// source is a JWKSIssuerKeySource over op's JWKS, with opts.
func (op sharedKeysOP) source(t *testing.T, opts ...keys.JWKSOption) *keys.JWKSIssuerKeySource {
	t.Helper()
	fetcher, err := fapihttp.New(op.jwks.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1, AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	jwksURI, err := fapi.ParseEndpointURL(op.jwks.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	src, err := keys.NewJWKSIssuerKeySource(fetcher, jwksURI, time.Minute, opts...)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	return src
}

// sign is an ID token op signs, claiming issuer, for the shared
// client_id.
func (op sharedKeysOP) sign(t *testing.T, issuer string, now time.Time) string {
	t.Helper()
	raw, err := token.IssueIDToken(token.IDTokenParams{
		Signer: op.key, Algorithm: fapi.ES256, KeyID: sharedKeysKeyID,
		Issuer: issuer, Subject: idTokenTestSubject, Audience: idTokenTestClientID,
		Nonce: idTokenTestNonce, Now: now, Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	return raw
}

// sharedKeysClient is a Client for issuer verifying with issuerKeys.
func sharedKeysClient(t *testing.T, issuer string, now time.Time, issuerKeys keys.IssuerKeySource) *Client {
	t.Helper()
	iss, err := fapi.ParseIssuerURL(issuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	return &Client{
		cfg: Config{
			Issuer:     iss,
			ClientID:   fapi.ClientID(idTokenTestClientID),
			Algorithms: Algorithms{IDToken: fapi.ES256, UserInfo: fapi.ES256},
			Limits:     Limits{MaxIDTokenLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second, MaxJOSECompactBytes: 16 * 1024},
		},
		deps: Dependencies{IssuerKeys: issuerKeys, Clock: idTokenFixedClock{now: now}},
	}
}

// refusesBoth checks that c refuses raw both as an ID token and as an
// issuer-signed JWS.
func refusesBoth(t *testing.T, c *Client, what, raw string) {
	t.Helper()
	ctx := context.Background()
	if v, err := c.validateIDToken(ctx, raw, "", idTokenTestNonce); err == nil {
		t.Errorf("%s: validateIDToken accepted it (sub %q)", what, v.Subject)
	}
	if _, err := c.VerifyIssuerJWS(ctx, raw); err == nil {
		t.Errorf("%s: VerifyIssuerJWS accepted it", what)
	}
}

// TestClientRefusesAnotherIssuersSignature: B's client, with B's own
// keys, refuses what A signed, whether it names A as its issuer or
// claims to be B's. Both keys share a kid, so the kid picks B's key,
// and A's signature doesn't verify under it.
func TestClientRefusesAnotherIssuersSignature(t *testing.T) {
	now := time.Now()
	opA, opB := newSharedKeysOP(t), newSharedKeysOP(t)
	clientB := sharedKeysClient(t, sharedKeysIssuerB, now, opB.source(t))

	if _, err := clientB.validateIDToken(context.Background(), opB.sign(t, sharedKeysIssuerB, now), "", idTokenTestNonce); err != nil {
		t.Fatalf("B's own ID token: %v", err)
	}
	refusesBoth(t, clientB, "signed by A, iss A", opA.sign(t, sharedKeysIssuerA, now))
	refusesBoth(t, clientB, "signed by A, iss B", opA.sign(t, sharedKeysIssuerB, now))
}

// TestIssuerBoundKeySourceSharedWithAnotherIssuersClient: a
// JWKSIssuerKeySource bound to A (keys.WithIssuer, as
// DiscoveredMetadata.IssuerKeySource builds it), given by mistake to
// B's client as well, serves A's client and refuses B's: what A signed
// claiming to be B's is never checked against A's keys on B's behalf.
func TestIssuerBoundKeySourceSharedWithAnotherIssuersClient(t *testing.T) {
	now := time.Now()
	opA := newSharedKeysOP(t)
	issuerA, err := fapi.ParseIssuerURL(sharedKeysIssuerA)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	shared := opA.source(t, keys.WithIssuer(issuerA))
	clientA := sharedKeysClient(t, sharedKeysIssuerA, now, shared)
	clientB := sharedKeysClient(t, sharedKeysIssuerB, now, shared)

	if _, err := clientA.validateIDToken(context.Background(), opA.sign(t, sharedKeysIssuerA, now), "", idTokenTestNonce); err != nil {
		t.Fatalf("A's own ID token at A's client: %v", err)
	}
	refusesBoth(t, clientB, "signed by A, iss B", opA.sign(t, sharedKeysIssuerB, now))
	refusesBoth(t, clientB, "signed by A, iss A", opA.sign(t, sharedKeysIssuerA, now))
}
