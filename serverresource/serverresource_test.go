package serverresource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func serverConfig(t *testing.T) server.Config {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return server.Config{
		Issuer:    issuer,
		Limits:    server.Limits{AccessTokenLifetime: 5 * time.Minute, MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
		Assurance: server.AssuranceDevelopment,
	}
}

func jwtAccessTokens(t *testing.T) server.JWTAccessTokens {
	t.Helper()
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := server.NewJWTAccessTokens(km, fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func serverDependencies(t *testing.T, accessTokens server.AccessTokenIssuer, now time.Time) server.Dependencies {
	t.Helper()
	return server.Dependencies{
		AccessTokens: accessTokens,
		Revocation:   memstore.NewRevocationStore(),
		Replay:       memstore.NewReplayStore(),
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}
}

func clientCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestVerifierSeesServerRevocation issues an mTLS-bound access token the
// way the server does, then checks the verifier accepts it until the
// server revokes it (as it does on authorization code reuse) — for both
// access-token formats.
func TestVerifierSeesServerRevocation(t *testing.T) {
	now := time.Now()
	for name, accessTokens := range map[string]server.AccessTokenIssuer{
		"jwt":    jwtAccessTokens(t),
		"opaque": server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cfg := serverConfig(t)
			deps := serverDependencies(t, accessTokens, now)
			verifier, err := serverresource.NewVerifier(cfg, deps, serverresource.Options{})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			cert := clientCertificate(t)
			thumbprint := sha256.Sum256(cert.Raw)
			token, revocationKey, err := accessTokens.IssueAccessToken(ctx, server.AccessTokenParams{
				ClientID: "client", Subject: "alice", Scope: []string{"openid"},
				Thumbprint:      base64.RawURLEncoding.EncodeToString(thumbprint[:]),
				SenderConstrain: storage.SenderConstrainMTLS,
				Issuer:          cfg.Issuer.String(), Audience: cfg.Issuer.String(),
				Now: now, Lifetime: cfg.Limits.AccessTokenLifetime, Random: rand.Reader,
			})
			if err != nil {
				t.Fatalf("IssueAccessToken: %v", err)
			}
			req := resource.VerifyRequest{
				Method: "GET", URL: &url.URL{Scheme: "https", Host: "as.example.com", Path: "/userinfo"},
				Authorization: "Bearer " + token, PeerCertificate: cert,
			}
			if _, err := verifier.Verify(ctx, req); err != nil {
				t.Fatalf("Verify(issued token) = %v, want nil", err)
			}
			if err := deps.Revocation.Revoke(ctx, revocationKey, now.Add(time.Hour)); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if _, err := verifier.Verify(ctx, req); err == nil {
				t.Fatal("Verify(revoked token) = nil error, want the server's revocation seen")
			}
		})
	}
}

// revokeOnly is a server.RevocationSink the verifier can't check.
type revokeOnly struct{}

func (revokeOnly) Revoke(context.Context, string, time.Time) error { return nil }

// customIssuer is an access-token issuer NewVerifier can't mirror.
type customIssuer struct{}

func (customIssuer) IssueAccessToken(context.Context, server.AccessTokenParams) (string, string, error) {
	return "", "", nil
}

func TestNewVerifierRejectsWhatItCannotMirror(t *testing.T) {
	now := time.Now()
	nonces := memstore.NewNonceStore()
	var nilJWT *server.JWTAccessTokens
	for name, tc := range map[string]struct {
		mutate  func(*server.Dependencies)
		opts    serverresource.Options
		wantErr string
	}{
		"revocation sink that can't be checked": {mutate: func(d *server.Dependencies) { d.Revocation = revokeOnly{} }, wantErr: "RevocationChecker"},
		"nil revocation sink":                   {mutate: func(d *server.Dependencies) { d.Revocation = nil }, wantErr: "RevocationChecker"},
		"custom access token issuer":            {mutate: func(d *server.Dependencies) { d.AccessTokens = customIssuer{} }, wantErr: "access token issuer"},
		"nil access token issuer pointer":       {mutate: func(d *server.Dependencies) { d.AccessTokens = nilJWT }, wantErr: "access token issuer"},
		"server's own nonce store": {
			mutate:  func(d *server.Dependencies) { d.Nonces = nonces },
			opts:    serverresource.Options{Nonces: nonces, NonceLifetime: time.Minute},
			wantErr: "Nonces",
		},
		"nonces without a lifetime": {opts: serverresource.Options{Nonces: memstore.NewNonceStore()}, wantErr: "serverresource"},
	} {
		t.Run(name, func(t *testing.T) {
			deps := serverDependencies(t, jwtAccessTokens(t), now)
			if tc.mutate != nil {
				tc.mutate(&deps)
			}
			_, err := serverresource.NewVerifier(serverConfig(t), deps, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewVerifier = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewVerifierAccepts(t *testing.T) {
	now := time.Now()
	jwt := jwtAccessTokens(t)
	opaque := server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
	for name, tc := range map[string]struct {
		mutate func(*server.Dependencies)
		opts   serverresource.Options
	}{
		"jwt pointer":        {mutate: func(d *server.Dependencies) { d.AccessTokens = &jwt }},
		"opaque pointer":     {mutate: func(d *server.Dependencies) { d.AccessTokens = &opaque }},
		"no revocation":      {mutate: func(d *server.Dependencies) { d.Revocation = server.NoRevocation{} }},
		"no revocation ptr":  {mutate: func(d *server.Dependencies) { d.Revocation = &server.NoRevocation{} }},
		"separate nonces":    {opts: serverresource.Options{Nonces: memstore.NewNonceStore(), NonceLifetime: time.Minute}},
		"nonces, server too": {mutate: func(d *server.Dependencies) { d.Nonces = memstore.NewNonceStore() }, opts: serverresource.Options{Nonces: memstore.NewNonceStore(), NonceLifetime: time.Minute}},
	} {
		t.Run(name, func(t *testing.T) {
			deps := serverDependencies(t, jwt, now)
			if tc.mutate != nil {
				tc.mutate(&deps)
			}
			if _, err := serverresource.NewVerifier(serverConfig(t), deps, tc.opts); err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
		})
	}
}

type declaredReplay struct {
	*memstore.ReplayStore
}

func (declaredReplay) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, AtomicConsume: true}
}

// TestNewVerifierInheritsAssurance: the verifier is checked at the
// server's own assurance level, so a production server's verifier
// refuses what resource.AssuranceProduction refuses.
func TestNewVerifierInheritsAssurance(t *testing.T) {
	now := time.Now()
	jwt := jwtAccessTokens(t)
	production := serverConfig(t)
	production.Assurance = server.AssuranceProduction

	t.Run("production refuses an undeclared replay store", func(t *testing.T) {
		_, err := serverresource.NewVerifier(production, serverDependencies(t, jwt, now), serverresource.Options{})
		if err == nil || !strings.Contains(err.Error(), "resource: dependencies: replay must implement storage.StoreAssurance under AssuranceProduction") {
			t.Fatalf("NewVerifier = %v, want the production replay check", err)
		}
	})
	t.Run("production refuses undeclared nonces", func(t *testing.T) {
		deps := serverDependencies(t, jwt, now)
		deps.Replay = declaredReplay{memstore.NewReplayStore()}
		deps.Revocation = server.NoRevocation{}
		_, err := serverresource.NewVerifier(production, deps, serverresource.Options{Nonces: memstore.NewNonceStore(), NonceLifetime: time.Minute})
		if err == nil || !strings.Contains(err.Error(), "resource: dependencies: nonces must implement storage.StoreAssurance") {
			t.Fatalf("NewVerifier = %v, want the production nonces check", err)
		}
	})
	t.Run("production accepts declared stores", func(t *testing.T) {
		deps := serverDependencies(t, jwt, now)
		deps.Replay = declaredReplay{memstore.NewReplayStore()}
		deps.Revocation = server.NoRevocation{}
		if _, err := serverresource.NewVerifier(production, deps, serverresource.Options{}); err != nil {
			t.Fatalf("NewVerifier = %v, want accepted", err)
		}
	})
	t.Run("production with HorizontallyScaled requires CrossInstanceConsistent", func(t *testing.T) {
		scaled := production
		scaled.HorizontallyScaled = true
		deps := serverDependencies(t, jwt, now)
		deps.Replay = declaredReplay{memstore.NewReplayStore()}
		deps.Revocation = server.NoRevocation{}
		_, err := serverresource.NewVerifier(scaled, deps, serverresource.Options{})
		if err == nil || !strings.Contains(err.Error(), "replay must declare CrossInstanceConsistent") {
			t.Fatalf("NewVerifier = %v, want the HorizontallyScaled check", err)
		}
	})
	t.Run("invalid server level", func(t *testing.T) {
		invalid := serverConfig(t)
		invalid.Assurance = 0
		_, err := serverresource.NewVerifier(invalid, serverDependencies(t, jwt, now), serverresource.Options{})
		if err == nil || !strings.Contains(err.Error(), "assurance level is invalid") {
			t.Fatalf("NewVerifier = %v, want the level refused", err)
		}
	})
}
