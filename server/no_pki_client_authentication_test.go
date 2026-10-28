package server_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestNoPKIClientAuthenticationKeepsFederationRPsFromBeingImpersonated
// covers a federation Relying Party whose public metadata lists
// tls_client_auth, with its subject DN, beside the private_key_jwt it
// uses: under NoPKIClientAuthentication automatic registration doesn't
// register tls_client_auth, so a self-signed certificate naming that DN
// authenticates as nobody, while the RP itself still authenticates with
// its key.
func TestNoPKIClientAuthenticationKeepsFederationRPsFromBeingImpersonated(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI, map[string]any{
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "tls_client_auth"},
		"tls_client_auth_subject_dn":            "CN=victim-rp",
	})
	srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.ClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
		deps.ClientCertificateTrust = server.NoPKIClientAuthentication{}
	})
	attackerCert := selfSignedTestClientCertWithSAN(t, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "victim-rp"}
	})
	_, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("grant_type", "client_credentials"),
			formParam("client_id", f.rpID),
			formParam("scope", "accounts"),
		}},
		DPoPProofs:      []string{createDPoPProof(t, generateKey(t), f.now)},
		PeerCertificate: attackerCert,
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("self-signed certificate naming the RP's DN: error code %q, want %q", code, server.ErrorInvalidClient)
	}

	if _, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("grant_type", "client_credentials"),
			formParam("client_assertion", automaticRegistrationAssertion(t, f)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("scope", "accounts"),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), f.now)},
	}); err != nil {
		t.Fatalf("the RP's own private_key_jwt: %v, want a token", err)
	}
}

// TestNoPKIClientAuthenticationRefusesStaticTLSClientAuth covers a
// statically registered tls_client_auth client at a server declaring
// NoPKIClientAuthentication: even a certificate carrying the registered
// DN is refused, while a self_signed_tls_client_auth client, bound by
// thumbprint, still authenticates.
func TestNoPKIClientAuthenticationRefusesStaticTLSClientAuth(t *testing.T) {
	cert := selfSignedTestClientCert(t)
	for name, tc := range map[string]struct {
		cfg  storage.RegisteredClientConfig
		want server.ErrorCode
	}{
		"tls_client_auth": {storage.RegisteredClientConfig{
			ClientAuthMethod: storage.ClientAuthMethodTLSClientAuth, ExpectedSubjectDN: cert.Subject.String(),
		}, server.ErrorInvalidClient},
		"self_signed_tls_client_auth": {storage.RegisteredClientConfig{
			ClientAuthMethod: storage.ClientAuthMethodSelfSignedTLSClientAuth, ExpectedCertificateThumbprint: mtls.Thumbprint(cert),
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionConfigAndDeps(t)
			clientCfg := tc.cfg
			clientCfg.ID = testClientID
			clientCfg.RedirectURIs = []fapi.RegisteredRedirectURI{testRedirectURI}
			clientCfg.SenderConstrain = storage.SenderConstrainMTLS
			clientCfg.AllowedScopes = []string{"openid", "accounts"}
			client, err := storage.NewRegisteredClient(clientCfg)
			if err != nil {
				t.Fatal(err)
			}
			deps.Clients = &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}}
			deps.ClientCertificateTrust = server.NoPKIClientAuthentication{}
			srv, err := server.New(cfg, deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
				PeerCertificate: cert,
			})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("PAR: %v, want accepted", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != tc.want {
				t.Fatalf("PAR: error code %q, want %q", code, tc.want)
			}
		})
	}
}

// TestNoPKIClientAuthenticationRefusesAllowingTLSClientAuth covers
// New refusing an automatic registration configuration that explicitly
// allows a CA-issued certificate method while the trust refuses them
// all.
func TestNoPKIClientAuthenticationRefusesAllowingTLSClientAuth(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)
	cfg, deps := automaticRegistrationTestConfig(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.AutomaticRegistration.AllowedClientAuthMethods = []storage.ClientAuthMethod{
			storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodTLSClientAuthSANDNS,
		}
		deps.ClientCertificateTrust = server.NoPKIClientAuthentication{}
	})
	if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "NoPKIClientAuthentication") {
		t.Fatalf("New = %v, want an error naming NoPKIClientAuthentication", err)
	}

	cfg.AutomaticRegistration.AllowedClientAuthMethods = []storage.ClientAuthMethod{
		storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodSelfSignedTLSClientAuth,
	}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New with no CA-issued certificate method allowed: %v", err)
	}
}

// TestNoPKIClientAuthenticationSkipsTLSClientAuthAtRegistration covers
// automatic registration itself leaving tls_client_auth out under
// NoPKIClientAuthentication: a Relying Party whose metadata offers only
// tls_client_auth isn't registered at all (OnResolutionFailure is told),
// rather than registered and then refused at every request.
func TestNoPKIClientAuthenticationSkipsTLSClientAuthAtRegistration(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI, map[string]any{
		"token_endpoint_auth_method":            "tls_client_auth",
		"token_endpoint_auth_methods_supported": []string{"tls_client_auth"},
		"tls_client_auth_subject_dn":            "CN=victim-rp",
	})
	var failure error
	srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.ClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
		cfg.AutomaticRegistration.OnResolutionFailure = func(_ context.Context, _ fapi.ClientID, err error) { failure = err }
		deps.ClientCertificateTrust = server.NoPKIClientAuthentication{}
	})
	_, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("grant_type", "client_credentials"),
			formParam("client_id", f.rpID),
			formParam("scope", "accounts"),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), f.now)},
		PeerCertificate: selfSignedTestClientCertWithSAN(t, func(c *x509.Certificate) {
			c.Subject = pkix.Name{CommonName: "victim-rp"}
		}),
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code %q, want %q", code, server.ErrorInvalidClient)
	}
	if failure == nil {
		t.Fatal("OnResolutionFailure wasn't called: the RP was registered for tls_client_auth")
	}
}

// TestAutomaticRegistrationRegistersPKIMethodsOnlyWhenVerifiedOrNamed
// covers which ClientCertificateTrust lets automatic registration
// register tls_client_auth for a Relying Party that lists it, with its
// public subject DN: TrustedClientCAs, which verifies the chain, does by
// default; ClientCertificateChainVerifiedUpstream and
// NoClientCertificateChainTrust do only when AllowedClientAuthMethods
// names it (the opt-in for a deployment whose TLS termination verifies
// the chain); otherwise a self-signed
// certificate naming that DN would authenticate as the RP.
func TestAutomaticRegistrationRegistersPKIMethodsOnlyWhenVerifiedOrNamed(t *testing.T) {
	for name, tc := range map[string]struct {
		trust      func(t *testing.T, cert *x509.Certificate) server.ClientCertificateTrust
		allowed    []storage.ClientAuthMethod
		registered bool
	}{
		"chain trust declined, default methods": {
			trust: func(*testing.T, *x509.Certificate) server.ClientCertificateTrust {
				return server.NoClientCertificateChainTrust{}
			},
		},
		"chain trust declined, tls_client_auth named": {
			trust: func(*testing.T, *x509.Certificate) server.ClientCertificateTrust {
				return server.NoClientCertificateChainTrust{}
			},
			allowed:    []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodTLSClientAuth},
			registered: true,
		},
		"verified upstream, default methods": {
			trust: func(*testing.T, *x509.Certificate) server.ClientCertificateTrust {
				return server.ClientCertificateChainVerifiedUpstream{}
			},
		},
		"verified upstream, tls_client_auth named": {
			trust: func(*testing.T, *x509.Certificate) server.ClientCertificateTrust {
				return server.ClientCertificateChainVerifiedUpstream{}
			},
			allowed:    []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodTLSClientAuth},
			registered: true,
		},
		"trusted CAs, default methods": {
			trust: func(_ *testing.T, cert *x509.Certificate) server.ClientCertificateTrust {
				roots := x509.NewCertPool()
				roots.AddCert(cert)
				return server.TrustedClientCAs{Roots: roots, Revocation: server.NoClientCertificateRevocationCheck{}}
			},
			registered: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := setupAutomaticRegistrationFixture(t, testRedirectURI, map[string]any{
				"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "tls_client_auth"},
				"tls_client_auth_subject_dn":            "CN=victim-rp",
			})
			// The RP's own key: OpenID Federation 1.0 §12.1.1.2 requires
			// the authenticating key to be in its RP JWK Set.
			cert := selfSignedTestClientCertForKey(t, f.rpOIDCKey, func(c *x509.Certificate) {
				c.Subject = pkix.Name{CommonName: "victim-rp"}
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			})
			srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, deps *server.Dependencies) {
				cfg.ClientCredentialsGrant = true
				cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
				cfg.AutomaticRegistration.AllowedClientAuthMethods = tc.allowed
				deps.ClientCertificateTrust = tc.trust(t, cert)
			})
			_, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP: server.FormRequest{Parameters: []server.FormParameter{
					formParam("grant_type", "client_credentials"),
					formParam("client_id", f.rpID),
					formParam("scope", "accounts"),
				}},
				DPoPProofs:      []string{createDPoPProof(t, generateKey(t), f.now)},
				PeerCertificate: cert,
			})
			if tc.registered {
				if err != nil {
					t.Fatalf("tls_client_auth with the RP's DN: %v, want a token", err)
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
				t.Fatalf("tls_client_auth with the RP's DN: error code %q, want %q", code, server.ErrorInvalidClient)
			}
			if _, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP: server.FormRequest{Parameters: []server.FormParameter{
					formParam("grant_type", "client_credentials"),
					formParam("client_assertion", automaticRegistrationAssertion(t, f)),
					formParam("client_assertion_type", clientassertion.AssertionType),
					formParam("scope", "accounts"),
				}},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), f.now)},
			}); err != nil {
				t.Fatalf("the RP's own private_key_jwt: %v, want a token", err)
			}
		})
	}
}
