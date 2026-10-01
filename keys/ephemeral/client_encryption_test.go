package ephemeral

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
)

// clientWithEncryptionKeys is a client's KeyManager with a signing key
// and one decryption key per algorithm in algs, and the JWK Set it
// would publish (keys.PublicJWKS): signing and encryption keys together.
func clientWithEncryptionKeys(t *testing.T, algs map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm) (*KeyManager, []byte) {
	t.Helper()
	km, err := NewKeyManagerWithDecryption(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.ES256}, algs)
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	var encryption []keys.EncryptionKeyUse
	for purpose, alg := range algs {
		encryption = append(encryption, keys.EncryptionKeyUse{Decrypter: km, Purpose: purpose, Algorithm: alg})
	}
	set, err := keys.PublicJWKS(context.Background(), []keys.SigningKeyUse{{Manager: km, Purpose: keys.ClientAuthentication, Algorithm: fapi.ES256}}, encryption)
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return km, jwks
}

func TestClientKeySourceResolvesEncryptionKeys(t *testing.T) {
	km, jwks := clientWithEncryptionKeys(t, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256, keys.UserInfoDecryption: fapi.ECDHESA256KW,
	})
	src, err := NewClientKeySource(nil, []ClientKeySpec{{ClientID: "client-1", JWKS: jwks}})
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}
	ctx := context.Background()

	for purpose, alg := range map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{keys.IDTokenDecryption: fapi.RSAOAEP256, keys.UserInfoDecryption: fapi.ECDHESA256KW} {
		want, err := km.EncryptionPublicKey(ctx, purpose, alg)
		if err != nil {
			t.Fatal(err)
		}
		set, err := src.ResolveEncryptionKeys(ctx, keys.ClientEncryptionKeyRequest{ClientID: "client-1", Purpose: keys.IDTokenEncryption, Algorithm: alg})
		if err != nil {
			t.Fatalf("ResolveEncryptionKeys(%v): %v", alg, err)
		}
		if len(set.Keys) != 1 || set.Keys[0].KeyID != want.KeyID || !reflect.DeepEqual(set.Keys[0].PublicKey, want.PublicKey) {
			t.Errorf("ResolveEncryptionKeys(%v) = %+v, want the client's key %q", alg, set.Keys, want.KeyID)
		}
		pinned, err := src.ResolveEncryptionKeys(ctx, keys.ClientEncryptionKeyRequest{ClientID: "client-1", Algorithm: alg, KeyID: "another"})
		if err != nil || len(pinned.Keys) != 0 {
			t.Errorf("ResolveEncryptionKeys(%v, unknown kid) = %+v, %v; want no keys", alg, pinned.Keys, err)
		}
	}

	// The encryption keys aren't also signature verification keys.
	for _, alg := range []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256} {
		set, err := src.ResolveVerificationKeys(ctx, keys.ClientKeyRequest{ClientID: "client-1", Algorithm: alg})
		if err != nil {
			t.Fatalf("ResolveVerificationKeys(%v): %v", alg, err)
		}
		want := 0
		if alg == fapi.ES256 {
			want = 1
		}
		if len(set.Keys) != want {
			t.Errorf("ResolveVerificationKeys(%v) = %d keys, want %d", alg, len(set.Keys), want)
		}
	}

	if _, err := src.ResolveEncryptionKeys(ctx, keys.ClientEncryptionKeyRequest{ClientID: "unknown", Algorithm: fapi.RSAOAEP256}); err == nil {
		t.Error("ResolveEncryptionKeys(unknown client) = nil error, want error")
	}
}

// TestClientKeySourceFetchesEncryptionKeys covers a jwks_uri: encryption
// keys come from the same fetched, cached JWK Set, and a pinned kid the
// cache lacks forces a refetch.
func TestClientKeySourceFetchesEncryptionKeys(t *testing.T) {
	km, jwks := clientWithEncryptionKeys(t, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{keys.IDTokenDecryption: fapi.RSAOAEP256})
	var fetches atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer ts.Close()
	fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	src, err := NewClientKeySource(fetcher, []ClientKeySpec{{ClientID: "client-1", JWKSURI: ts.URL + "/jwks"}}, WithCacheTTL(time.Minute))
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}
	ctx := context.Background()
	want, err := km.EncryptionPublicKey(ctx, keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		set, err := src.ResolveEncryptionKeys(ctx, keys.ClientEncryptionKeyRequest{ClientID: "client-1", Algorithm: fapi.RSAOAEP256})
		if err != nil || len(set.Keys) != 1 || set.Keys[0].KeyID != want.KeyID {
			t.Fatalf("ResolveEncryptionKeys = %+v, %v; want the client's key", set.Keys, err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("fetched %d times for two lookups within the TTL, want 1", got)
	}
	if _, err := src.ResolveEncryptionKeys(ctx, keys.ClientEncryptionKeyRequest{ClientID: "client-1", Algorithm: fapi.RSAOAEP256, KeyID: "rotated-in"}); err != nil {
		t.Fatalf("ResolveEncryptionKeys(pinned kid): %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Errorf("fetched %d times after a pinned kid the cache lacked, want 2", got)
	}
}

// TestClientKeySourceReportsFetchFailures covers a jwks_uri that fails
// or serves something that isn't a JWK Set: both kinds of lookup fail.
func TestClientKeySourceReportsFetchFailures(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"server error": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusInternalServerError) },
		"not a JWK Set": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewTLSServer(handler)
			defer ts.Close()
			fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{
				MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1, AllowLoopbackHTTP: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			src, err := NewClientKeySource(fetcher, []ClientKeySpec{{ClientID: "client-1", JWKSURI: ts.URL + "/jwks"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err := src.ResolveEncryptionKeys(ctx, keys.ClientEncryptionKeyRequest{ClientID: "client-1", Algorithm: fapi.RSAOAEP256}); err == nil {
				t.Error("ResolveEncryptionKeys = nil error, want the fetch failure")
			}
			if _, err := src.ResolveVerificationKeys(ctx, keys.ClientKeyRequest{ClientID: "client-1", Algorithm: fapi.ES256}); err == nil {
				t.Error("ResolveVerificationKeys = nil error, want the fetch failure")
			}
		})
	}
}

func TestClientKeySourcePinnedVerificationKeyID(t *testing.T) {
	_, jwks := clientWithEncryptionKeys(t, nil)
	src, err := NewClientKeySource(nil, []ClientKeySpec{{ClientID: "client-1", JWKS: jwks}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: "client-1", Algorithm: fapi.ES256, KeyID: "another"})
	if err != nil || len(set.Keys) != 0 {
		t.Fatalf("ResolveVerificationKeys(unknown kid) = %+v, %v; want no keys", set.Keys, err)
	}
}
