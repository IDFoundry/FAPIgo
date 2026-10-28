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
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// withURLs is opts with ResourceURLs naming every origin the tests'
// protected endpoints are called at.
func withURLs(t testing.TB, opts serverresource.Options) serverresource.Options {
	t.Helper()
	for _, raw := range []string{"https://as.example.com", "https://api.saas.example", "https://issuer-b.example.com"} {
		u, err := fapi.ParseEndpointURL(raw)
		if err != nil {
			t.Fatalf("ParseEndpointURL(%q): %v", raw, err)
		}
		opts.ResourceURLs = append(opts.ResourceURLs, u)
	}
	return opts
}

// ReadsSystemTime declares resource.ClockAssurance, so the tests running
// under AssuranceProduction with a fixedClock pinned at time.Now get
// past NewVerifier's clock check.
func (fixedClock) ReadsSystemTime() bool { return true }

func serverConfig(t *testing.T) server.Config {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return server.Config{
		Subjects:  server.PublicSubjects(),
		Issuer:    issuer,
		Limits:    server.Limits{AccessTokenLifetime: 5 * time.Minute, MaxDPoPProofAge: time.Minute, MaxClockSkew: 10 * time.Second},
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
			verifier, err := serverresource.NewVerifier(cfg, deps, withURLs(t, serverresource.Options{}))
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
			_, err := serverresource.NewVerifier(serverConfig(t), deps, withURLs(t, tc.opts))
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
			if _, err := serverresource.NewVerifier(serverConfig(t), deps, withURLs(t, tc.opts)); err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
		})
	}
}

// TestNewVerifierDerivesNonces covers how a production verifier's DPoP
// nonces follow Options.Nonces and the server's own Dependencies.Nonces.
func TestNewVerifierDerivesNonces(t *testing.T) {
	production := serverConfig(t)
	production.Assurance = server.AssuranceProduction
	production.Deployment = server.DeploymentSingleInstance
	for name, tc := range map[string]struct {
		server  storage.NonceStore
		opts    storage.NonceStore
		wantErr string
	}{
		"server declines":                      {server: server.NoDPoPNonces{}},
		"server declines by pointer":           {server: &server.NoDPoPNonces{}},
		"options decline":                      {opts: resource.NoDPoPNonces{}},
		"options decline by pointer":           {opts: &resource.NoDPoPNonces{}},
		"options decline with server's":        {server: memstore.NewNonceStore(), opts: server.NoDPoPNonces{}},
		"server's own decline as options":      {server: server.NoDPoPNonces{}, opts: server.NoDPoPNonces{}},
		"server nonces, none of its own":       {server: memstore.NewNonceStore(), wantErr: "Options.Nonces is required under AssuranceProduction"},
		"neither":                              {wantErr: "nonces is required under AssuranceProduction"},
		"options a nil *resource.NoDPoPNonces": {opts: (*resource.NoDPoPNonces)(nil), wantErr: "nonces is a nil *NoDPoPNonces"},
	} {
		t.Run(name, func(t *testing.T) {
			deps := serverDependencies(t, jwtAccessTokens(t), time.Now())
			deps.Replay = declaredReplay{memstore.NewReplayStore()}
			deps.Revocation = server.NoRevocation{}
			deps.Nonces = tc.server
			v, err := serverresource.NewVerifier(production, deps, withURLs(t, serverresource.Options{Nonces: tc.opts}))
			assertDerivedNonces(t, v, err, tc.wantErr)
		})
	}
}

// assertDerivedNonces checks err mentions wantErr, or, with wantErr
// empty, that v was built and declines nonces.
func assertDerivedNonces(t *testing.T, v *resource.Verifier, err error, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("NewVerifier = %v, want an error mentioning %q", err, wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("NewVerifier = %v, want accepted", err)
	}
	if nonce, err := v.IssueDPoPNonce(context.Background()); nonce != "" || err != nil {
		t.Fatalf("IssueDPoPNonce = %q, %v; want nonces declined", nonce, err)
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
	production.Deployment = server.DeploymentSingleInstance

	t.Run("production refuses an undeclared replay store", func(t *testing.T) {
		_, err := serverresource.NewVerifier(production, serverDependencies(t, jwt, now), withURLs(t, serverresource.Options{}))
		if err == nil || !strings.Contains(err.Error(), "resource: dependencies: replay must implement storage.StoreAssurance under AssuranceProduction") {
			t.Fatalf("NewVerifier = %v, want the production replay check", err)
		}
	})
	t.Run("production refuses undeclared nonces", func(t *testing.T) {
		deps := serverDependencies(t, jwt, now)
		deps.Replay = declaredReplay{memstore.NewReplayStore()}
		deps.Revocation = server.NoRevocation{}
		_, err := serverresource.NewVerifier(production, deps, withURLs(t, serverresource.Options{Nonces: memstore.NewNonceStore(), NonceLifetime: time.Minute}))
		if err == nil || !strings.Contains(err.Error(), "resource: dependencies: nonces must implement storage.StoreAssurance") {
			t.Fatalf("NewVerifier = %v, want the production nonces check", err)
		}
	})
	t.Run("production accepts declared stores", func(t *testing.T) {
		deps := serverDependencies(t, jwt, now)
		deps.Replay = declaredReplay{memstore.NewReplayStore()}
		deps.Revocation = server.NoRevocation{}
		deps.Nonces = server.NoDPoPNonces{}
		if _, err := serverresource.NewVerifier(production, deps, withURLs(t, serverresource.Options{})); err != nil {
			t.Fatalf("NewVerifier = %v, want accepted", err)
		}
	})
	t.Run("production declining revocation needs short access tokens", func(t *testing.T) {
		deps := serverDependencies(t, jwt, now)
		deps.Replay = declaredReplay{memstore.NewReplayStore()}
		deps.Revocation = server.NoRevocation{}
		long := production
		long.Limits.AccessTokenLifetime = 16 * time.Minute
		_, err := serverresource.NewVerifier(long, deps, withURLs(t, serverresource.Options{}))
		if err == nil || !strings.Contains(err.Error(), "NoRevocationUntilExpiry.MaxTokenLifetime must be at most") {
			t.Fatalf("NewVerifier(AccessTokenLifetime 16m) = %v, want the unrevocable lifetime refused", err)
		}
		long.Assurance = server.AssuranceDevelopment
		if _, err := serverresource.NewVerifier(long, deps, withURLs(t, serverresource.Options{})); err != nil {
			t.Fatalf("NewVerifier(development, AccessTokenLifetime 16m) = %v, want accepted", err)
		}
	})
	t.Run("production with DeploymentHorizontallyScaled requires CrossInstanceConsistent", func(t *testing.T) {
		scaled := production
		scaled.Deployment = server.DeploymentHorizontallyScaled
		deps := serverDependencies(t, jwt, now)
		deps.Replay = declaredReplay{memstore.NewReplayStore()}
		deps.Revocation = server.NoRevocation{}
		_, err := serverresource.NewVerifier(scaled, deps, withURLs(t, serverresource.Options{}))
		if err == nil || !strings.Contains(err.Error(), "replay must declare CrossInstanceConsistent") {
			t.Fatalf("NewVerifier = %v, want the DeploymentHorizontallyScaled check", err)
		}
	})
	t.Run("invalid server level", func(t *testing.T) {
		invalid := serverConfig(t)
		invalid.Assurance = 0
		_, err := serverresource.NewVerifier(invalid, serverDependencies(t, jwt, now), withURLs(t, serverresource.Options{}))
		if err == nil || !strings.Contains(err.Error(), "assurance level is invalid") {
			t.Fatalf("NewVerifier = %v, want the level refused", err)
		}
	})
}

// TestNewVerifierRefusesInvalidDeployment: a server Deployment outside
// the two defined has no resource equivalent to map to.
func TestNewVerifierRefusesInvalidDeployment(t *testing.T) {
	cfg := serverConfig(t)
	cfg.Deployment = server.DeploymentHorizontallyScaled + 1
	deps := serverDependencies(t, jwtAccessTokens(t), time.Now())
	if _, err := serverresource.NewVerifier(cfg, deps, withURLs(t, serverresource.Options{})); err == nil || !strings.Contains(err.Error(), "deployment is invalid") {
		t.Fatalf("NewVerifier(invalid deployment) = %v, want refusal", err)
	}
}

// TestNewVerifierResolvesPairwiseSubjects: with a reversible deriver the
// verifier looks a self-contained token's pairwise sub up through the
// server's own deriver and prefix; with a one-way deriver the server's
// opaque records already keep the internal subject.
func TestNewVerifierResolvesPairwiseSubjects(t *testing.T) {
	now := time.Now()
	prefix, err := pairwise.NewPrefix("pw:")
	if err != nil {
		t.Fatal(err)
	}
	mapping, oneWay := testDerivers(t)
	for name, tc := range map[string]struct {
		deriver      pairwise.Deriver
		accessTokens server.AccessTokenIssuer
	}{
		"reversible, jwt":    {mapping, jwtAccessTokens(t)},
		"one-way, opaque":    {oneWay, server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}},
		"reversible, opaque": {mapping, server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cfg := serverConfig(t)
			cfg.Subjects = server.SubjectConfig{Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPerClient, Prefix: prefix}
			deps := serverDependencies(t, tc.accessTokens, now)
			deps.PairwiseSubjects = tc.deriver
			verifier, err := serverresource.NewVerifier(cfg, deps, withURLs(t, serverresource.Options{}))
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			clientSub, token, cert := issuePairwiseToken(t, cfg, tc.accessTokens, tc.deriver, prefix, now)
			authz, err := verifier.Verify(ctx, resource.VerifyRequest{
				Method: "GET", URL: &url.URL{Scheme: "https", Host: "as.example.com", Path: "/userinfo"},
				Authorization: "Bearer " + token, PeerCertificate: cert,
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if authz.InternalSubject != "alice" || authz.ClientSubject != clientSub {
				t.Errorf("Subject, ClientSubject = %q, %q; want alice, %q", authz.InternalSubject, authz.ClientSubject, clientSub)
			}
		})
	}
}

// testDerivers is a mapping (reversible) deriver and an HMAC (one-way)
// one.
func testDerivers(t *testing.T) (mapping, oneWay pairwise.Deriver) {
	t.Helper()
	mapping, err := pairwise.NewMapping(memstore.NewPairwiseSubjectStore())
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i + 1)
	}
	oneWay, err = pairwise.NewHMAC(hmacKey)
	if err != nil {
		t.Fatal(err)
	}
	return mapping, oneWay
}

// issuePairwiseToken issues, through accessTokens, a token for the user
// alice at a client in the sector rp.example, as the server would: its
// sub the pairwise one deriver and prefix give, its internal subject
// alice. It returns that sub, the token, and the client certificate the
// token is bound to.
// issuePairwiseToken issues at now, the verifier's own fixed time, so the
// token's lifetime is measured from the same instant the verifier checks it
// against.
func issuePairwiseToken(t *testing.T, cfg server.Config, accessTokens server.AccessTokenIssuer, deriver pairwise.Deriver, prefix pairwise.Prefix, now time.Time) (string, string, *x509.Certificate) {
	t.Helper()
	ctx := context.Background()
	in, err := pairwise.NewInput(cfg.Issuer.String(), "rp.example", "alice")
	if err != nil {
		t.Fatal(err)
	}
	body, err := deriver.DerivePairwiseSubject(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	clientSub := prefix.String() + body
	cert := clientCertificate(t)
	thumbprint := sha256.Sum256(cert.Raw)
	token, _, err := accessTokens.IssueAccessToken(ctx, server.AccessTokenParams{
		ClientID: "client", Subject: clientSub, InternalSubject: "alice", Scope: []string{"openid"},
		Claims:          map[string]json.RawMessage{"pairwise_sector": json.RawMessage(`"rp.example"`)},
		Thumbprint:      base64.RawURLEncoding.EncodeToString(thumbprint[:]),
		SenderConstrain: storage.SenderConstrainMTLS,
		Issuer:          cfg.Issuer.String(), Audience: cfg.Issuer.String(),
		Now: now, Lifetime: cfg.Limits.AccessTokenLifetime, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	return clientSub, token, cert
}

// mapResolver resolves the one sub it holds to alice.
type mapResolver struct{ sub string }

func (r *mapResolver) ResolveSubject(_ context.Context, _, _, sub string) (string, error) {
	if sub != r.sub {
		return "", pairwise.ErrSubjectNotFound
	}
	return "alice", nil
}

// TestNewVerifierPassesTheServersSubjectResolver: with a one-way deriver
// with JWT access tokens, the verifier resolves pairwise subs through
// the resolver the server declares.
func TestNewVerifierPassesTheServersSubjectResolver(t *testing.T) {
	prefix, err := pairwise.NewPrefix("pw:")
	if err != nil {
		t.Fatal(err)
	}
	_, oneWay := testDerivers(t)
	cfg := serverConfig(t)
	cfg.Subjects = server.SubjectConfig{Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPerClient, Prefix: prefix}
	accessTokens := jwtAccessTokens(t)
	now := time.Now()
	deps := serverDependencies(t, accessTokens, now)
	deps.PairwiseSubjects = oneWay
	resolver := &mapResolver{}
	deps.PairwiseSubjectResolver = resolver
	verifier, err := serverresource.NewVerifier(cfg, deps, withURLs(t, serverresource.Options{}))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	clientSub, token, cert := issuePairwiseToken(t, cfg, accessTokens, oneWay, prefix, now)
	resolver.sub = clientSub
	authz, err := verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: &url.URL{Scheme: "https", Host: "as.example.com", Path: "/userinfo"},
		Authorization: "Bearer " + token, PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if authz.InternalSubject != "alice" || authz.ClientSubject != clientSub {
		t.Errorf("Subject, ClientSubject = %q, %q; want alice, %q", authz.InternalSubject, authz.ClientSubject, clientSub)
	}
}

// TestNewVerifierRequiresResourceURLs: the server's configuration names
// no protected endpoint, so the verifier's own URLs must be given.
func TestNewVerifierRequiresResourceURLs(t *testing.T) {
	deps := serverDependencies(t, jwtAccessTokens(t), time.Now())
	if _, err := serverresource.NewVerifier(serverConfig(t), deps, serverresource.Options{}); err == nil || !strings.Contains(err.Error(), "resource_urls is required") {
		t.Fatalf("NewVerifier(no ResourceURLs) = %v, want resource_urls required", err)
	}
}
