package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// selfSignedClientCert is selfSignedCert's client-certificate
// counterpart — ExtKeyUsageClientAuth instead of ExtKeyUsageServerAuth,
// no IP SAN (nothing here validates this certificate's identity; RFC
// 8705 §3 sender-constraining only cares about its thumbprint).
func selfSignedClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client cert key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "smoke-test-mtls-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestSmokeMTLSFlow is TestSmokeAuthorizationCodeFlow's mTLS
// counterpart: a client registered storage.SenderConstrainMTLS drives
// PAR -> authorize -> consent -> token exchange -> UserInfo, presenting
// a client certificate instead of a DPoP proof at the token and
// UserInfo calls, over a second listener standing in for -mtls. This is
// the go/no-go gate for the mtls_endpoint_aliases/PeerCertificate
// wiring before ever pointing a live suite run at it.
func TestSmokeMTLSFlow(t *testing.T) {
	serverCert, pool := selfSignedCert(t)
	clientCert := selfSignedClientCert(t)

	primaryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen (primary): %v", err)
	}
	primaryTLS := tls.NewListener(primaryListener, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})

	mtlsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen (mtls): %v", err)
	}
	mtlsTLS := tls.NewListener(mtlsListener, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
	})

	issuer, err := fapi.ParseIssuerURL(fmt.Sprintf("https://%s", primaryListener.Addr().String()))
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}
	endpoints, err := buildEndpoints(issuer, false)
	if err != nil {
		t.Fatalf("build endpoints: %v", err)
	}
	userinfoURL, err := buildUserinfoURL(issuer, false)
	if err != nil {
		t.Fatalf("build userinfo url: %v", err)
	}
	mtlsEndpoints, err := buildMTLSEndpoints(issuer, mtlsListener.Addr().String(), false)
	if err != nil {
		t.Fatalf("build mtls endpoints: %v", err)
	}
	// /userinfo has no server.MTLSEndpoints alias of its own (that
	// struct only covers server.Server's own protocol endpoints) — this
	// binary's separate protected-resource endpoint needs its own
	// mtls-listener URL built the same way buildMTLSEndpoints derives
	// its three.
	mtlsUserinfoURL, err := fapi.ParseEndpointURL(fmt.Sprintf("https://%s/userinfo", mtlsListener.Addr().String()))
	if err != nil {
		t.Fatalf("build mtls userinfo url: %v", err)
	}

	clientKeyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAuthentication: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("build client key manager: %v", err)
	}
	clientAuthKey, err := clientKeyManager.PublicKey(context.Background(), keys.ClientAuthentication, fapi.ES256)
	if err != nil {
		t.Fatalf("resolve client auth public key: %v", err)
	}
	jwk, err := jose.NewJWK(clientAuthKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("build client jwk: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(clientAuthKey.KeyID).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal client jwk: %v", err)
	}
	inlineJWKS := json.RawMessage(fmt.Sprintf(`{"keys":[%s]}`, jwkJSON))

	const testClientID = fapi.ClientID("smoke-test-mtls-client")
	const testRedirectURI = "https://rp.smoketest.internal/callback"

	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
		SenderConstrain:          storage.SenderConstrainMTLS,
	})
	if err != nil {
		t.Fatalf("build registered client: %v", err)
	}

	resolved := ResolvedConfig{
		ListenAddr:        primaryListener.Addr().String(),
		MTLSListenAddr:    mtlsListener.Addr().String(),
		Issuer:            issuer,
		Profile:           server.ProfileFAPISecurity,
		DefaultSubject:    smokeSubject,
		Algorithms:        server.RecommendedAlgorithms(),
		Limits:            server.RecommendedLimits(),
		AccessTokenFormat: AccessTokenFormatJWT,
		Clients:           []storage.RegisteredClient{registered},
		ClientKeys:        []ephemeral.ClientKeySpec{{ClientID: testClientID, JWKS: inlineJWKS}},
		AdvertisedScopes:  []string{"openid", "accounts"},
		MTLSEndpoints:     mtlsEndpoints,
	}

	mux, err := newServerMux(resolved, false, false, false, false, false)
	if err != nil {
		t.Fatalf("build server mux: %v", err)
	}
	primaryServer := &http.Server{Handler: mux}
	go primaryServer.Serve(primaryTLS)
	t.Cleanup(func() { primaryServer.Close() })
	mtlsServer := &http.Server{Handler: mux}
	go mtlsServer.Serve(mtlsTLS)
	t.Cleanup(func() { mtlsServer.Close() })

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCert},
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// metadataHandler's own mtls_endpoint_aliases.userinfo_endpoint
	// merge branch: fapi2-security-profile-final-test-claims-parameter-identity-claims
	// resolves userinfo_endpoint straight from discovery rather than a
	// suite plan's own resource.resourceUrl override, so this alias is
	// what makes that lookup land on the mTLS listener instead of the
	// plain one (confirmed live against the OIDF suite; see
	// buildMTLSUserinfoURL's own doc comment).
	metadataRes, err := httpClient.Get(issuer.String() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	var metadataDoc struct {
		MTLSEndpointAliases struct {
			UserinfoEndpoint string `json:"userinfo_endpoint"`
		} `json:"mtls_endpoint_aliases"`
	}
	decodeErr := json.NewDecoder(metadataRes.Body).Decode(&metadataDoc)
	metadataRes.Body.Close()
	if decodeErr != nil {
		t.Fatalf("decode metadata: %v", decodeErr)
	}
	if metadataDoc.MTLSEndpointAliases.UserinfoEndpoint != mtlsUserinfoURL.String() {
		t.Errorf("mtls_endpoint_aliases.userinfo_endpoint = %q, want %q", metadataDoc.MTLSEndpointAliases.UserinfoEndpoint, mtlsUserinfoURL.String())
	}

	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 20, RequestTimeout: 10 * time.Second, MaxRedirects: 0,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("build fetcher: %v", err)
	}
	issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, endpoints.JWKS, time.Minute)
	if err != nil {
		t.Fatalf("build issuer key source: %v", err)
	}

	clientCfg := client.Config{
		Issuer:      issuer,
		ClientID:    testClientID,
		RedirectURI: testRedirectURI,
		Endpoints: client.Endpoints{
			Authorization:              endpoints.Authorization,
			Token:                      mtlsEndpoints.Token,
			PushedAuthorizationRequest: endpoints.PushedAuthorizationRequest,
			UserInfo:                   mtlsUserinfoURL,
		},
		Profile:         client.ProfileFAPISecurity,
		SenderConstrain: storage.SenderConstrainMTLS,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256,
			IDToken:              fapi.ES256,
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute,
			SessionLifetime:         10 * time.Minute,
			MaxIDTokenLifetime:      10 * time.Minute,
			MaxClockSkew:            10 * time.Second,
			HTTPTimeout:             10 * time.Second,
			MaxHTTPResponseBytes:    1 << 16,
			MaxJOSECompactBytes:     16 * 1024,
		},
	}
	clientDeps := client.Dependencies{
		Sessions:   newMemSessionStore(),
		Keys:       clientKeyManager,
		IssuerKeys: issuerKeys,
		HTTP:       httpClient,
		Clock:      client.SystemClock{},
		Random:     rand.Reader,
	}
	c, err := client.New(clientCfg, clientDeps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	h := &smokeHarness{t: t, client: c, httpClient: httpClient, authorize: endpoints.Authorization.String()}
	ctx := context.Background()
	handle := h.runToConsent(ctx, []string{"openid", "accounts"})
	finalQuery := h.submitDecision(ctx, handle, "approve", []string{"openid", "accounts"})

	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: finalQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", success.Tokens.TokenType, "Bearer")
	}

	userInfo, err := c.FetchUserInfo(ctx, success.Tokens)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if userInfo.Subject == "" {
		t.Errorf("UserInfo response carries no sub claim")
	}

	// Presenting the mTLS-bound token without a client certificate must
	// be rejected — connect through the primary (non-cert) listener
	// instead, proving Verify's SenderConstrain cross-check actually
	// runs, not just that the happy path works.
	plainClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL.String(), nil)
	if err != nil {
		t.Fatalf("build userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+success.Tokens.AccessToken.Reveal())
	res, err := plainClient.Do(req)
	if err != nil {
		t.Fatalf("GET userinfo without client cert: %v", err)
	}
	defer res.Body.Close()
	// "a client certificate is required" is invalid_request/400 — the
	// caller sent no credential at all, the same status
	// resource.Verify's "DPoP header is required" case uses for a DPoP-
	// bound token, distinct from invalid_token/401 (a credential was
	// presented but didn't check out).
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("GET userinfo without client cert: status = %d, want %d", res.StatusCode, http.StatusBadRequest)
	}
	if www := res.Header.Get("WWW-Authenticate"); !strings.Contains(www, "invalid_request") {
		t.Errorf("WWW-Authenticate = %q, want it to mention invalid_request", www)
	}
}
