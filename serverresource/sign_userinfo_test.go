package serverresource_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// errNoSuchClient is a client repository's answer for a client it
// doesn't know.
var errNoSuchClient = errors.New("no such client")

// failingClients is a client repository that answers every lookup with
// err.
type failingClients struct{ err error }

func (f failingClients) ResolveClient(context.Context, fapi.ClientID) (storage.RegisteredClient, error) {
	return storage.RegisteredClient{}, f.err
}

// noClientKeys resolves no client keys: signing a UserInfo response
// never needs one.
type noClientKeys struct{}

func (noClientKeys) ResolveVerificationKeys(context.Context, keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	return keys.VerificationKeySet{}, errors.New("no client keys")
}

// userInfoServer is a server that signs UserInfo responses, and the
// repository holding its two registered clients, rp-1 and rp-2.
func userInfoServer(t *testing.T) (*server.Server, storage.ClientRepository) {
	t.Helper()
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.ES256, keys.UserInfoSigning: fapi.ES256,
		keys.IDTokenSigning: fapi.ES256, keys.JARMSigning: fapi.ES256,
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect := fapi.RegisteredRedirectURI("https://rp.example.com/cb")
	var registered []storage.RegisteredClient
	for _, id := range []fapi.ClientID{"rp-1", "rp-2"} {
		client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID: id, RedirectURIs: []fapi.RegisteredRedirectURI{redirect},
			ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"},
		})
		if err != nil {
			t.Fatal(err)
		}
		registered = append(registered, client)
	}
	clients := memstore.NewClientRepository(registered)

	cfg := serverConfig(t)
	endpoint := func(path string) fapi.URL {
		u, err := fapi.ParseEndpointURL("https://as.example.com" + path)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	cfg.Endpoints = server.Endpoints{
		Authorization: endpoint("/authorize"), Token: endpoint("/token"),
		PushedAuthorizationRequest: endpoint("/par"), JWKS: endpoint("/jwks"),
	}
	cfg.Profile = server.ProfileFAPISecurity
	cfg.Algorithms = server.AlgorithmPolicy{
		ClientAssertion: server.AlgorithmSet{fapi.ES256}, RequestObject: server.AlgorithmSet{fapi.ES256},
		JARM: fapi.ES256, IDToken: fapi.ES256, UserInfo: fapi.ES256,
	}
	cfg.Limits = server.Limits{
		PushedRequestLifetime: 90 * time.Second, MaxClientAssertionLifetime: time.Minute,
		MaxRequestObjectLifetime: time.Minute, InteractionLifetime: 5 * time.Minute,
		AuthorizationCodeLifetime: time.Minute, JARMResponseLifetime: time.Minute,
		AccessTokenLifetime: 5 * time.Minute, IDTokenLifetime: 5 * time.Minute,
		MaxIDTokenClaimsBytes: 4096, RefreshTokenLifetime: 5 * time.Minute,
		MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second,
	}
	srv, err := server.New(cfg, server.Dependencies{
		Clients: clients, Transactions: memstore.NewTransactionStore(), Grants: memstore.NewGrantStore(),
		Replay: memstore.NewReplayStore(), ClientKeys: noClientKeys{}, Keys: km,
		AccessTokens: server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256}, Revocation: memstore.NewRevocationStore(),
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  fixedClock{now: time.Now()}, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, clients
}

// signedPayload is the claims inside a signed compact JWS.
func signedPayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("signed response %q isn't a compact JWS", compact)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// TestSignUserInfoResponseIsForTheTokensClient covers binding the
// signed UserInfo response to the access token: it's addressed to the
// client the token was issued to, about the token's subject, and
// refused for any other subject or for a client no longer registered.
func TestSignUserInfoResponseIsForTheTokensClient(t *testing.T) {
	srv, clients, authz, claims := signUserInfoFixture(t)

	signed, err := serverresource.SignUserInfoResponse(context.Background(), srv, clients, authz, claims)
	if err != nil {
		t.Fatalf("SignUserInfoResponse: %v", err)
	}
	payload := signedPayload(t, signed)
	if payload["aud"] != "rp-2" || payload["sub"] != "user-1" || payload["iss"] != "https://as.example.com" {
		t.Fatalf("payload = %v, want aud rp-2, sub user-1 and the issuer", payload)
	}

	for name, c := range map[string]map[string]json.RawMessage{
		"another subject": {"sub": json.RawMessage(`"user-2"`)},
		"no subject":      {"email": json.RawMessage(`"sam@example.com"`)},
		"malformed sub":   {"sub": json.RawMessage(`42`)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := serverresource.SignUserInfoResponse(context.Background(), srv, clients, authz, c); err == nil || !strings.Contains(err.Error(), "isn't the access token's subject") {
				t.Fatalf("SignUserInfoResponse(%s) error = %v, want the subject refused", name, err)
			}
		})
	}

	t.Run("empty subject", func(t *testing.T) {
		empty := authz
		empty.Subject = ""
		if _, err := serverresource.SignUserInfoResponse(context.Background(), srv, clients, empty, map[string]json.RawMessage{"sub": json.RawMessage(`""`)}); err == nil {
			t.Fatal("SignUserInfoResponse(empty subject) succeeded")
		}
	})

}

// TestSignUserInfoResponseReportsLookupAndSigningFailures covers how
// SignUserInfoResponse reports a client it can't resolve, an
// unavailable client repository, and a failure to sign: an unknown
// client is 401 invalid_token, an outage 500 server_error, both keeping
// the repository's error, and a signing failure the server's own error.
func TestSignUserInfoResponseReportsLookupAndSigningFailures(t *testing.T) {
	srv, clients, authz, claims := signUserInfoFixture(t)

	t.Run("unknown client", func(t *testing.T) {
		unknown := authz
		unknown.ClientID = "rp-gone"
		_, err := serverresource.SignUserInfoResponse(context.Background(), srv, clients, unknown, claims)
		var rerr *resource.Error
		if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidToken || rerr.HTTPStatus() != http.StatusUnauthorized {
			t.Fatalf("SignUserInfoResponse(unknown client) error = %v, want 401 invalid_token", err)
		}
	})

	t.Run("unknown client keeps the repository's error", func(t *testing.T) {
		unknown := authz
		unknown.ClientID = "rp-gone"
		_, err := serverresource.SignUserInfoResponse(context.Background(), srv, failingClients{err: errNoSuchClient}, unknown, claims)
		var rerr *resource.Error
		if !errors.As(err, &rerr) || rerr.HTTPStatus() != http.StatusUnauthorized || !errors.Is(err, errNoSuchClient) {
			t.Fatalf("SignUserInfoResponse(unknown client) error = %v, want 401 keeping the repository's error", err)
		}
	})

	for name, repoErr := range map[string]error{
		"store unavailable": fmt.Errorf("db: %w", storage.ErrStoreUnavailable),
		"context cancelled": fmt.Errorf("db: %w", context.Canceled),
		"deadline exceeded": fmt.Errorf("db: %w", context.DeadlineExceeded),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := serverresource.SignUserInfoResponse(context.Background(), srv, failingClients{err: repoErr}, authz, claims)
			var rerr *resource.Error
			if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorServerError || rerr.HTTPStatus() != http.StatusInternalServerError || !errors.Is(err, repoErr) {
				t.Fatalf("SignUserInfoResponse(%s) error = %v, want 500 server_error keeping the repository's error", name, err)
			}
		})
	}

	t.Run("signing failure", func(t *testing.T) {
		reserved := map[string]json.RawMessage{"sub": json.RawMessage(`"user-1"`), "aud": json.RawMessage(`"rp-1"`)}
		_, err := serverresource.SignUserInfoResponse(context.Background(), srv, clients, authz, reserved)
		var srvErr *server.Error
		if !errors.As(err, &srvErr) || srvErr.Code() != server.ErrorServerError {
			t.Fatalf("SignUserInfoResponse(reserved aud) error = %v, want the server's error", err)
		}
	})
}

// signUserInfoFixture returns a server, its client repository, the
// authorization context of an openid access token for user-1 issued to
// rp-2, and UserInfo claims about user-1.
func signUserInfoFixture(t *testing.T) (*server.Server, storage.ClientRepository, resource.AuthorizationContext, map[string]json.RawMessage) {
	t.Helper()
	srv, clients := userInfoServer(t)
	authz := resource.AuthorizationContext{Subject: "user-1", ClientID: "rp-2", Scopes: []string{"openid"}}
	claims := map[string]json.RawMessage{"sub": json.RawMessage(`"user-1"`), "email": json.RawMessage(`"sam@example.com"`)}
	return srv, clients, authz, claims
}
