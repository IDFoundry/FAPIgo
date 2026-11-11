package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// issuerKeysCacheTTL is how long the client caches the server's JWKS.
const issuerKeysCacheTTL = 5 * time.Minute

// clientShape is what a leg exercises: the profile, how the client
// authenticates, how its tokens are sender-constrained, and whether it
// uses CIBA. The leg's clientConfig supplies the registration.
type clientShape struct {
	profile    client.Profile
	authMTLS   bool // self_signed_tls_client_auth instead of private_key_jwt
	senderMTLS bool // certificate-bound tokens instead of DPoP
	ciba       bool
	cibaPing   bool
}

// newClient builds a client.Client for one leg the way an integrator
// would: discovery through a hardened fetcher, the issuer's JWKS from
// its metadata, the library's recommended algorithms and limits, and
// NewFromDiscovery to fill in endpoints (mtls_endpoint_aliases where
// this client does mutual TLS) and raise the RFC 9207 iss policy.
//
// The client is built at AssuranceDevelopment, which the test
// environment needs in three places AssuranceProduction refuses: the
// server runs on localhost, so the transport and fetcher allow loopback
// hosts; authorization sessions live in memstore; and the keys are the
// run's throwaway keys, held in memory with no declared custody.
func newClient(ctx context.Context, rc runConfig, leg legConfig, shape clientShape) (*client.Client, error) {
	httpClient, err := newHTTPClient(rc, leg.TLSClient)
	if err != nil {
		return nil, err
	}
	fetcherConfig := fapihttp.RecommendedConfig()
	fetcherConfig.AllowLoopbackHosts = true
	fetcher, err := fapihttp.New(httpClient, fetcherConfig)
	if err != nil {
		return nil, fmt.Errorf("build fetcher: %w", err)
	}

	issuer, err := fapi.ParseIssuerURL(rc.Issuer)
	if err != nil {
		return nil, fmt.Errorf("parse issuer: %w", err)
	}
	discovered, err := client.Discover(ctx, fetcher, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	issuerKeys, err := discovered.IssuerKeySource(fetcher, issuerKeysCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("issuer key source: %w", err)
	}

	keyManager, err := newKeyManager(leg, shape)
	if err != nil {
		return nil, err
	}

	cfg := client.Config{
		ClientID:                       fapi.ClientID(leg.ClientID),
		RedirectURI:                    leg.RedirectURI,
		Profile:                        shape.profile,
		Algorithms:                     algorithmsFor(shape),
		Limits:                         client.RecommendedLimits(),
		Assurance:                      client.AssuranceDevelopment,
		AuthorizationResponseIssPolicy: client.TolerateAbsentAuthorizationResponseIss, // NewFromDiscovery raises this when the server advertises iss
	}
	if err := registeredAlgorithms(leg, &cfg.Algorithms); err != nil {
		return nil, err
	}
	if shape.authMTLS {
		method, err := tlsClientAuthMethod(leg.TLSClientAuth)
		if err != nil {
			return nil, err
		}
		cfg.ClientAuthMethod = method
	}
	if shape.senderMTLS {
		cfg.SenderConstrain = storage.SenderConstrainMTLS
	}
	if shape.ciba {
		cfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
		if shape.cibaPing {
			cfg.BackchannelTokenDeliveryMode = storage.BackchannelTokenDeliveryModePing
		}
	}

	deps := client.Dependencies{
		Keys:       keyManager,
		IssuerKeys: issuerKeys,
		HTTP:       httpClient,
		Clock:      client.SystemClock{},
		Random:     rand.Reader,
	}
	if leg.RedirectURI != "" {
		deps.Sessions = memstore.NewSessionStore()
	}
	cl, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("construct client: %w", err)
	}
	return cl, nil
}

// registeredAlgorithms sets the response signing algorithms the leg's
// client is registered with, where the run's configuration names them.
func registeredAlgorithms(leg legConfig, algs *client.Algorithms) error {
	for _, registered := range []struct {
		name  string
		value string
		into  *fapi.SignatureAlgorithm
	}{
		{"id_token_signed_response_alg", leg.IDTokenSignedResponseAlg, &algs.IDToken},
		{"userinfo_signed_response_alg", leg.UserInfoSignedResponseAlg, &algs.UserInfo},
		{"authorization_signed_response_alg", leg.AuthorizationSignedResponseAlg, &algs.JARM},
	} {
		if registered.value == "" {
			continue
		}
		alg, err := fapi.ParseSignatureAlgorithm(registered.value)
		if err != nil {
			return fmt.Errorf("%s: %w", registered.name, err)
		}
		*registered.into = alg
	}
	return nil
}

// tlsClientAuthMethod maps a leg's tls_client_auth setting to the
// client's mutual-TLS authentication method.
func tlsClientAuthMethod(name string) (storage.ClientAuthMethod, error) {
	switch name {
	case "", "self_signed_tls_client_auth":
		return storage.ClientAuthMethodSelfSignedTLSClientAuth, nil
	case "tls_client_auth":
		return storage.ClientAuthMethodTLSClientAuth, nil
	default:
		return 0, fmt.Errorf("unknown tls_client_auth %q", name)
	}
}

func algorithmsFor(shape clientShape) client.Algorithms {
	var unused fapi.SignatureAlgorithm
	algs := client.RecommendedAlgorithms()
	if shape.authMTLS {
		algs.ClientAuthentication = unused
	}
	if shape.senderMTLS {
		algs.DPoP = unused
	}
	if shape.profile == client.ProfileFAPISecurityWithMessageSigning {
		algs.RequestObject = fapi.ES256
		algs.JARM = fapi.ES256
	}
	if shape.ciba {
		algs.BackchannelAuthenticationRequest = fapi.ES256
	}
	return algs
}

// newHTTPClient is fapihttp.NewClient's hardened transport, trusting
// the run's test CA and presenting tlsClient's certificate if set.
func newHTTPClient(rc runConfig, tlsClient *tlsFiles) (*http.Client, error) {
	roots, err := loadCAPool(rc.CAFile)
	if err != nil {
		return nil, err
	}
	transport := fapihttp.RecommendedTransportConfig()
	transport.RootCAs = roots
	transport.AllowLoopbackHosts = true
	if tlsClient != nil {
		cert, err := tls.LoadX509KeyPair(tlsClient.CertFile, tlsClient.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		transport.Certificates = []tls.Certificate{cert}
	}
	httpClient, err := fapihttp.NewClient(transport)
	if err != nil {
		return nil, fmt.Errorf("build HTTP client: %w", err)
	}
	return httpClient, nil
}

func loadCAPool(file string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(file) // #nosec G304 -- the runner's own CA file
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no PEM certificate", file)
	}
	return pool, nil
}

// newKeyManager holds the leg's registered signing key for every
// purpose it signs for, and a fresh DPoP key for a DPoP client. A
// client that signs nothing (certificate authentication and
// certificate-bound tokens) gets none.
func newKeyManager(leg legConfig, shape clientShape) (keys.KeyManager, error) {
	var specs []keys.SignerSpec
	if leg.SigningKeyFile != "" {
		signer, err := loadECKey(leg.SigningKeyFile)
		if err != nil {
			return nil, err
		}
		var purposes []keys.SigningPurpose
		if !shape.authMTLS {
			purposes = append(purposes, keys.ClientAuthentication)
		}
		if shape.profile == client.ProfileFAPISecurityWithMessageSigning {
			purposes = append(purposes, keys.RequestObjectSigning)
		}
		if shape.ciba {
			purposes = append(purposes, keys.BackchannelAuthenticationRequestSigning)
		}
		for _, purpose := range purposes {
			specs = append(specs, keys.SignerSpec{Purpose: purpose, Algorithm: fapi.ES256, Signer: signer, KeyID: leg.SigningKeyID})
		}
	}
	if !shape.senderMTLS {
		dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate DPoP key: %w", err)
		}
		specs = append(specs, keys.SignerSpec{Purpose: keys.DPoPProofSigning, Algorithm: fapi.ES256, Signer: dpopKey})
	}
	if len(specs) == 0 {
		return nil, nil
	}
	return keys.NewKeyManagerFromSigners(specs)
}

func loadECKey(file string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(file) // #nosec G304 -- the runner's own key file
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", file)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not an EC key")
	}
	return ecKey, nil
}
