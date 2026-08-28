package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// discoverForAlgorithmTests spins up a discovery document advertising
// ES256 for id_token/request_object/authorization (JARM) and
// RSA-OAEP-256/A256GCM for id_token encryption, and returns the
// resulting DiscoveredMetadata — the fixture every SupportsAlgorithms
// test below checks against.
func discoverForAlgorithmTests(t *testing.T) client.DiscoveredMetadata {
	t.Helper()
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := discoveryDoc{
			Issuer:                              ts.URL,
			AuthorizationEndpoint:               ts.URL + "/authorize",
			TokenEndpoint:                       ts.URL + "/token",
			PushedAuthorizationRequestEndpoint:  ts.URL + "/par",
			JWKSURI:                             ts.URL + "/jwks",
			IDTokenSigningAlgValuesSupported:    []string{"ES256"},
			RequestObjectSigningAlgValues:       []string{"ES256"},
			AuthorizationSigningAlgValues:       []string{"ES256"},
			IDTokenEncryptionAlgValuesSupported: []string{"RSA-OAEP-256"},
			IDTokenEncryptionEncValuesSupported: []string{"A256GCM"},

			UserinfoSigningAlgValuesSupported:    []string{"ES256"},
			UserinfoEncryptionAlgValuesSupported: []string{"RSA-OAEP-256"},
			UserinfoEncryptionEncValuesSupported: []string{"A256GCM"},

			BackchannelAuthenticationRequestSigningAlgValuesSupported: []string{"ES256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	}))
	t.Cleanup(ts.Close)

	tsIssuer, err := fapi.ParseIssuerURL(ts.URL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL(ts.URL): %v", err)
	}
	md, err := client.Discover(context.Background(), newDiscoveryFetcher(t, ts), tsIssuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return md
}

func TestSupportsAlgorithmsAcceptsMatchingIDToken(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	if err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256}); err != nil {
		t.Fatalf("SupportsAlgorithms(matching id_token): %v", err)
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedIDToken(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	if err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.PS256}); err == nil {
		t.Fatal("SupportsAlgorithms(unsupported id_token) = nil error, want error")
	}
}

func TestSupportsAlgorithmsSkipsRequestObjectAndJARMWhenZero(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	// RequestObject/JARM left zero — the baseline-profile shape — must
	// not be checked even though the issuer's own advertised support
	// for them differs from whatever a message-signing profile might
	// have configured.
	if err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256}); err != nil {
		t.Fatalf("SupportsAlgorithms(RequestObject/JARM unset): %v", err)
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedRequestObject(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256, RequestObject: fapi.PS256})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported request object alg) = nil error, want error")
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedJARM(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256, JARM: fapi.PS256})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported JARM alg) = nil error, want error")
	}
}

func TestSupportsAlgorithmsAcceptsMatchingEncryption(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.RSAOAEP256, IDTokenContentEncryption: fapi.A256GCM,
	})
	if err != nil {
		t.Fatalf("SupportsAlgorithms(matching encryption): %v", err)
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedEncryptionKeyManagement(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.ECDHESA256KW, IDTokenContentEncryption: fapi.A256GCM,
	})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported key management) = nil error, want error")
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedContentEncryption(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{
		IDToken: fapi.ES256, IDTokenKeyManagement: fapi.RSAOAEP256, IDTokenContentEncryption: fapi.A256CBCHS512,
	})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported content encryption) = nil error, want error")
	}
}

func TestSupportsAlgorithmsSkipsEncryptionWhenNotConfigured(t *testing.T) {
	md := discoverForAlgorithmTests(t) // advertises encryption support
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256})
	if err != nil {
		t.Fatalf("SupportsAlgorithms(encryption not configured): %v", err)
	}
}

func TestSupportsAlgorithmsSkipsUserInfoWhenZero(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	// UserInfo left zero — a caller expecting only a plain-JSON UserInfo
	// response — must not be checked even though the issuer advertises
	// JWT UserInfo support this caller never asked for.
	if err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256}); err != nil {
		t.Fatalf("SupportsAlgorithms(UserInfo unset): %v", err)
	}
}

func TestSupportsAlgorithmsAcceptsMatchingUserInfo(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256, UserInfo: fapi.ES256})
	if err != nil {
		t.Fatalf("SupportsAlgorithms(matching userinfo): %v", err)
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedUserInfo(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256, UserInfo: fapi.PS256})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported userinfo alg) = nil error, want error")
	}
}

func TestSupportsAlgorithmsAcceptsMatchingUserInfoEncryption(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{
		IDToken: fapi.ES256, UserInfoKeyManagement: fapi.RSAOAEP256, UserInfoContentEncryption: fapi.A256GCM,
	})
	if err != nil {
		t.Fatalf("SupportsAlgorithms(matching userinfo encryption): %v", err)
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedUserInfoEncryptionKeyManagement(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{
		IDToken: fapi.ES256, UserInfoKeyManagement: fapi.ECDHESA256KW, UserInfoContentEncryption: fapi.A256GCM,
	})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported userinfo key management) = nil error, want error")
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedUserInfoContentEncryption(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{
		IDToken: fapi.ES256, UserInfoKeyManagement: fapi.RSAOAEP256, UserInfoContentEncryption: fapi.A256CBCHS512,
	})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported userinfo content encryption) = nil error, want error")
	}
}

func TestSupportsAlgorithmsSkipsUserInfoEncryptionWhenNotConfigured(t *testing.T) {
	md := discoverForAlgorithmTests(t) // advertises userinfo encryption support
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256, UserInfo: fapi.ES256})
	if err != nil {
		t.Fatalf("SupportsAlgorithms(userinfo encryption not configured): %v", err)
	}
}

func TestSupportsAlgorithmsSkipsBackchannelAuthenticationRequestWhenZero(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	// A caller not using CIBA leaves this zero — must not be checked
	// even though the issuer advertises CIBA support this caller never
	// asked for.
	if err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256}); err != nil {
		t.Fatalf("SupportsAlgorithms(BackchannelAuthenticationRequest unset): %v", err)
	}
}

func TestSupportsAlgorithmsAcceptsMatchingBackchannelAuthenticationRequest(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256, BackchannelAuthenticationRequest: fapi.ES256})
	if err != nil {
		t.Fatalf("SupportsAlgorithms(matching backchannel authentication request alg): %v", err)
	}
}

func TestSupportsAlgorithmsRejectsUnsupportedBackchannelAuthenticationRequest(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{IDToken: fapi.ES256, BackchannelAuthenticationRequest: fapi.PS256})
	if err == nil {
		t.Fatal("SupportsAlgorithms(unsupported backchannel authentication request alg) = nil error, want error")
	}
}

// TestSupportsAlgorithmsIgnoresClientOwnSigningChoices confirms
// ClientAuthentication/DPoP are never checked — a server doesn't
// advertise which algorithms it accepts for those the way it does for
// what it produces or accepts as an encryption target.
func TestSupportsAlgorithmsIgnoresClientOwnSigningChoices(t *testing.T) {
	md := discoverForAlgorithmTests(t)
	err := md.SupportsAlgorithms(client.Algorithms{
		IDToken: fapi.ES256, ClientAuthentication: fapi.EdDSA, DPoP: fapi.EdDSA,
	})
	if err != nil {
		t.Fatalf("SupportsAlgorithms(ClientAuthentication/DPoP never advertised anywhere): %v", err)
	}
}
