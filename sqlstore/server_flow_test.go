package sqlstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// The client of this file's servers, registered in their clients
// table. It authenticates with a self-signed TLS client certificate
// (self_signed_tls_client_auth) and its tokens are bound to it (RFC
// 8705), so a test drives the server's token endpoint with nothing to
// sign: FAPIgo's own client-side JWT helpers are internal.
const (
	flowClientID  = fapi.ClientID("mtls-app")
	flowRedirect  = "https://app.example/cb"
	flowVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
	flowChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	flowSubject   = "user-1"
)

// flowClient is the client's certificate, which authenticates it.
type flowClient struct {
	t    testing.TB
	cert *x509.Certificate
}

// newFlowClient registers the client in d's clients table, with a new
// self-signed certificate, valid long enough for any clock a test moves.
func newFlowClient(t testing.TB, d *sqlstore.DB) flowClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: string(flowClientID)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(1000 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	thumbprint := sha256.Sum256(cert.Raw)
	must(t, d.Clients().Put(context.Background(), storage.RegisteredClientConfig{
		ID: flowClientID, RedirectURIs: []fapi.RegisteredRedirectURI{flowRedirect},
		ClientAuthMethod:              storage.ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint: base64.RawURLEncoding.EncodeToString(thumbprint[:]),
		SenderConstrain:               storage.SenderConstrainMTLS,
		AllowedScopes:                 []string{"accounts", "offline_access"},
	}))
	return flowClient{t: t, cert: cert}
}

// form is a form request of name and value pairs.
func form(pairs ...string) server.FormRequest {
	var f server.FormRequest
	for i := 0; i+1 < len(pairs); i += 2 {
		f.Parameters = append(f.Parameters, server.FormParameter{Name: pairs[i], Value: pairs[i+1]})
	}
	return f
}

// code runs a pushed authorization request for "accounts" and
// "offline_access" on srv and the user's approval of it, with grantID,
// returning the authorization code.
func (c flowClient) code(ctx context.Context, srv *server.Server, now time.Time, grantID string) string {
	c.t.Helper()
	pushed, err := srv.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: form("client_id", string(flowClientID), "response_type", "code", "redirect_uri", flowRedirect,
			"scope", "accounts offline_access", "code_challenge", flowChallenge, "code_challenge_method", "S256"),
		PeerCertificate: c.cert,
	})
	must(c.t, err)
	action, err := srv.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: pushed.RequestURI.String(), ClientID: flowClientID})
	must(c.t, err)
	required, ok := action.(server.InteractionRequired)
	if !ok {
		c.t.Fatalf("BeginAuthorization = %T, want server.InteractionRequired", action)
	}
	subjectID, err := server.NewSubjectID(flowSubject)
	must(c.t, err)
	subject, err := server.NewAuthenticatedSubject(subjectID)
	must(c.t, err)
	authn, err := server.NewAuthenticationContext(now, "acr-1", []string{"pwd"})
	must(c.t, err)
	result, err := srv.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authn, server.GrantedAuthorization{Scope: required.Interaction.Scope, GrantID: grantID}),
	})
	must(c.t, err)
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		c.t.Fatalf("CompleteAuthorization = %T, want server.AuthorizationRedirect", result)
	}
	destination := redirect.Destination().URL()
	return destination.Query().Get("code")
}

// exchange redeems code on srv, returning the refresh token issued.
func (c flowClient) exchange(ctx context.Context, srv *server.Server, code string) (string, error) {
	tokens, err := srv.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP: form("client_id", string(flowClientID), "grant_type", "authorization_code", "code", code,
			"redirect_uri", flowRedirect, "code_verifier", flowVerifier),
		PeerCertificate: c.cert,
	})
	switch {
	case err != nil:
		return "", err
	case !tokens.HasRefreshToken:
		return "", errors.New("the code exchange issued no refresh token")
	}
	return tokens.RefreshToken.Reveal(), nil
}

// refresh redeems refreshToken on srv.
func (c flowClient) refresh(srv *server.Server, refreshToken string) error {
	_, err := srv.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:            form("client_id", string(flowClientID), "grant_type", "refresh_token", "refresh_token", refreshToken),
		PeerCertificate: c.cert,
	})
	return err
}

// movingClock is a server.Clock a test moves forward. It declares
// server.ClockAssurance, which AssuranceProduction requires, and which
// it only earns until it's first moved: build every server first.
type movingClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *movingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// ReadsSystemTime implements server.ClockAssurance — see movingClock.
func (c *movingClock) ReadsSystemTime() bool { return true }

func (c *movingClock) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(by)
}

// flowDeployment is the AssuranceProduction deployment productionServer
// builds over d, with grants as its GrantStore, d's GrantRegistry and
// clock as its clock.
func flowDeployment(t *testing.T, d *sqlstore.DB, grants storage.GrantStore, clock server.Clock) (server.Config, server.Dependencies) {
	t.Helper()
	deployment := server.DeploymentHorizontallyScaled
	if d.Dialect() == sqlstore.SQLite {
		deployment = server.DeploymentSingleInstance
	}
	cfg, deps := productionServer(t, d, deployment)
	deps.Grants, deps.GrantRegistry, deps.Clock = grants, d.GrantRegistry(), clock
	return cfg, deps
}

// newServer is server.New(cfg, deps) with cfg's refresh token lifetime
// set to lifetime.
func newServer(t *testing.T, cfg server.Config, deps server.Dependencies, lifetime time.Duration) *server.Server {
	t.Helper()
	cfg.Limits.RefreshTokenLifetime = lifetime
	srv, err := server.New(cfg, deps)
	must(t, err)
	return srv
}

// isInvalidGrant reports whether err is the server's invalid_grant.
func isInvalidGrant(err error) bool {
	var e *server.Error
	return errors.As(err, &e) && e.Code() == server.ErrorInvalidGrant
}

// A grant revoked with RevokeGrant stays revoked after its revocation
// record is swept, even where a longer refresh token lifetime applies
// than the record was sized from (here an instance issuing for 500 days
// beside one revoking with an hour's): the store revokes the grant's
// refresh token itself (storage.GrantRefreshTokenRevoker), leaving
// nothing for that lifetime to accept. Before, the token outlived the
// record, and a refresh on the long-lived instance brought the grant
// back.
func TestRevokedGrantStaysRevokedAfterItsRecordIsSwept(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for name, grants := range map[string]func(*sqlstore.DB) storage.GrantStore{
			"Grants":         func(d *sqlstore.DB) storage.GrantStore { return d.Grants() },
			"BatchingGrants": func(d *sqlstore.DB) storage.GrantStore { return d.BatchingGrants() },
		} {
			t.Run(name, func(t *testing.T) { checkRevokedGrantStaysRevoked(t, dialect, grants) })
		}
	})
}

func checkRevokedGrantStaysRevoked(t *testing.T, dialect sqlstore.Dialect, grants func(*sqlstore.DB) storage.GrantStore) {
	ctx := context.Background()
	p := newPlace(t, dialect)
	d := p.migrated()
	_, db := p.open()
	app := newFlowClient(t, d)
	clock := &movingClock{now: time.Now()}
	cfg, deps := flowDeployment(t, d, grants(d), clock)
	long, short := newServer(t, cfg, deps, 500*24*time.Hour), newServer(t, cfg, deps, time.Hour)
	refreshToken, err := app.exchange(ctx, long, app.code(ctx, long, clock.Now(), "grant-1"))
	must(t, err)

	clock.advance(time.Minute)
	must(t, short.RevokeGrant(ctx, "grant-1"))
	if redeemable(t, d.Grants(), sha256.Sum256([]byte(refreshToken))) {
		t.Fatal("RevokeGrant left the grant's refresh token in the store")
	}

	// Past the grant's record, which lasts at least 400 days: Sweep
	// removes it, so only the store can still refuse the token.
	clock.advance(401 * 24 * time.Hour)
	_, err = d.Sweep(ctx, clock.Now())
	must(t, err)
	if n := countRows(t, p, db, "revocations"); n != 0 {
		t.Fatalf("setup: %d revocation records left after the Sweep, want none", n)
	}
	if err := app.refresh(long, refreshToken); !isInvalidGrant(err) {
		t.Fatalf("refresh on the 500-day instance after the grant's record was swept = %v, want invalid_grant", err)
	}
	subject, err := server.NewSubjectID(flowSubject)
	must(t, err)
	if listed, err := long.ListGrants(ctx, subject); err != nil || len(listed) != 0 {
		t.Fatalf("ListGrants after the grant's record was swept = %d grants, %v, want none", len(listed), err)
	}
}
