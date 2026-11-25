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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// A CIBA request's decisions racing each other and the client's polls,
// through server.Server's API on this package's stores (see
// server_concurrency_test.go).

// cibaClientID is the CIBA client of cibaRace's server: it
// authenticates with a self-signed certificate, as the flow's client
// does, and signs its backchannel authentication requests with a key
// registered in the clients table.
const cibaClientID = fapi.ClientID("ciba-app")

// cibaGrantType is the CIBA grant's grant_type (CIBA Core §10.1).
const cibaGrantType = "urn:openid:params:grant-type:ciba"

// cibaRace is a server, with a moving clock, and its CIBA client.
type cibaRace struct {
	t        *testing.T
	srv      *server.Server
	clock    *movingClock
	interval time.Duration
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
}

// newCIBARace registers the CIBA client in fresh tables on dialect and
// builds flowDeployment's server over them, with a clock tests move.
func newCIBARace(t *testing.T, dialect sqlstore.Dialect) *cibaRace {
	t.Helper()
	d := freshDB(t, dialect)
	r := &cibaRace{t: t, clock: &movingClock{now: time.Now()}}
	var err error
	r.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	r.cert = selfSignedClientCertificate(t, string(cibaClientID))
	thumbprint := sha256.Sum256(r.cert.Raw)
	must(t, d.Clients().PutWithKeys(context.Background(), storage.RegisteredClientConfig{
		ID: cibaClientID, RedirectURIs: []fapi.RegisteredRedirectURI{flowRedirect},
		ClientAuthMethod:                          storage.ClientAuthMethodSelfSignedTLSClientAuth,
		ExpectedCertificateThumbprint:             base64.RawURLEncoding.EncodeToString(thumbprint[:]),
		SenderConstrain:                           storage.SenderConstrainMTLS,
		AllowedScopes:                             []string{"openid", "accounts"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		Sector: "app.example",
	}, sqlstore.ClientKeyRegistration{JWKS: publicJWKS(t, &r.key.PublicKey, "ciba-key")}))
	cfg, deps := flowDeployment(t, d, d.Grants(), r.clock)
	r.interval = cfg.Limits.BackchannelAuthenticationPollInterval
	r.srv, err = server.New(cfg, deps)
	must(t, err)
	return r
}

// selfSignedClientCertificate is a new self-signed TLS client
// certificate for commonName.
func selfSignedClientCertificate(t testing.TB, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(1000 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	return cert
}

// publicJWKS is a JWK Set of pub, kid kid.
func publicJWKS(t testing.TB, pub *ecdsa.PublicKey, kid string) json.RawMessage {
	t.Helper()
	point, err := pub.Bytes() // 0x04 || X || Y
	must(t, err)
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:])
	return json.RawMessage(fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q,"alg":"ES256","use":"sig"}]}`, x, y, kid))
}

// requestObject is a signed CIBA backchannel authentication request of
// the client's, for "openid accounts" and the flow's end user, issued
// now by r's clock.
func (r *cibaRace) requestObject() string {
	r.t.Helper()
	now := r.clock.Now()
	claims, err := json.Marshal(map[string]any{
		"iss": string(cibaClientID), "aud": "https://as.example", "jti": randomHex(16),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(30 * time.Second).Unix(),
		"scope": "openid accounts", "login_hint": flowSubject,
	})
	must(r.t, err)
	header := `{"alg":"ES256","typ":"oauth-authz-req+jwt","kid":"ciba-key"}`
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	rr, s, err := ecdsa.Sign(rand.Reader, r.key, digest[:])
	must(r.t, err)
	signature := make([]byte, 64)
	rr.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// begin starts a CIBA request, returning it.
func (r *cibaRace) begin() server.BackchannelInteractionRequired {
	r.t.Helper()
	action, err := r.srv.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP:            form("client_id", string(cibaClientID), "request", r.requestObject()),
		PeerCertificate: r.cert,
	})
	must(r.t, err)
	switch a := action.(type) {
	case server.BackchannelInteractionRequired:
		return a
	case server.BackchannelAuthenticationLocalError:
		r.t.Fatalf("BeginBackchannelAuthentication: %v", a.Error)
	}
	r.t.Fatalf("BeginBackchannelAuthentication = %T", action)
	return server.BackchannelInteractionRequired{}
}

// poll is the client's token request for authReqID.
func (r *cibaRace) poll(authReqID string) error {
	_, err := r.srv.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP:            form("client_id", string(cibaClientID), "grant_type", cibaGrantType, "auth_req_id", authReqID),
		PeerCertificate: r.cert,
	})
	return err
}

// errorCode is err's server error code, or "" for another error.
func errorCode(err error) server.ErrorCode {
	var e *server.Error
	if errors.As(err, &e) {
		return e.Code()
	}
	return ""
}

// The end user's approval and denial of one CIBA request, racing each
// other and the client's polls: exactly one decision is recorded, the
// other refused with invalid_request; and the request yields tokens
// exactly once if it was approved, and never if it was denied — across
// the racing polls and one made once the poll interval has passed,
// each of which is otherwise pending, slow_down, access_denied or, once
// the request is spent, invalid_grant.
func TestServerCIBADecisionsRacingPolls(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		r := newCIBARace(t, dialect)
		var approved int
		for range serverRaceIterations {
			approved += oneIf(r.raceDecisions())
		}
		t.Logf("%s: %d races, %d approvals won", dialect, serverRaceIterations, approved)
	})
}

// cibaOutcomes are what a race of a CIBA request's decisions and polls
// returned.
type cibaOutcomes struct {
	approveErr, denyErr error
	polls               []error
}

// raceDecisions runs one race of an approval, a denial and
// serverRaceCallers polls of a new CIBA request, then a poll once the
// interval has passed, checks what they returned, and reports whether
// the approval won.
func (r *cibaRace) raceDecisions() bool {
	r.t.Helper()
	request := r.begin()
	authReqID := request.AuthReqID.String()
	approval := r.approval()
	var out cibaOutcomes
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		out.approveErr = r.srv.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
			Handle: request.Handle, Result: approval,
		})
	})
	wg.Go(func() {
		<-start
		out.denyErr = r.srv.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
			Handle: request.Handle, Result: server.Deny("the user declined"),
		})
	})
	wg.Go(func() {
		<-start
		out.polls = concurrently(serverRaceCallers, func() error { return r.poll(authReqID) })
	})
	close(start)
	wg.Wait()

	r.clock.advance(r.interval + time.Second)
	out.polls = append(out.polls, r.poll(authReqID))
	return r.checkDecisions(out)
}

// approval is the approval of the request by the flow's end user,
// authenticated now by r's clock, granting "openid accounts".
func (r *cibaRace) approval() server.InteractionResult {
	r.t.Helper()
	subject, err := server.NewAuthenticatedSubject(mustSubject(r.t))
	must(r.t, err)
	authn, err := server.NewAuthenticationContext(r.clock.Now(), "acr-1", []string{"pwd"})
	must(r.t, err)
	return server.Authorize(subject, authn, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}})
}

// checkDecisions checks out, returning whether the approval won.
func (r *cibaRace) checkDecisions(out cibaOutcomes) bool {
	r.t.Helper()
	approved := out.approveErr == nil
	if approved == (out.denyErr == nil) {
		r.t.Fatalf("racing decisions: approve = %v, deny = %v, want exactly one recorded", out.approveErr, out.denyErr)
	}
	if loser := errors.Join(out.approveErr, out.denyErr); errorCode(loser) != server.ErrorInvalidRequest {
		r.t.Errorf("the losing decision = %v, want invalid_request", loser)
	}
	tokens, denials := 0, 0
	for _, err := range out.polls {
		switch errorCode(err) {
		case "":
			if err != nil {
				r.t.Errorf("a poll = %v, want a server error", err)
			}
			tokens += oneIf(err == nil)
		case server.ErrorAccessDenied:
			denials++
		case server.ErrorAuthorizationPending, server.ErrorSlowDown, server.ErrorInvalidGrant:
		default:
			r.t.Errorf("a poll = %v, want tokens, authorization_pending, slow_down, access_denied or invalid_grant", err)
		}
	}
	if want := oneIf(approved); tokens != want {
		r.t.Errorf("the request (approved %v) yielded tokens %d times, want %d; polls %v", approved, tokens, want, out.polls)
	}
	if approved && denials != 0 {
		r.t.Errorf("an approved request's polls were access_denied %d times; polls %v", denials, out.polls)
	}
	return approved
}
