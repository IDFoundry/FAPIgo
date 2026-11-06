package sqlstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// clientJWKS is a JWK Set of one fresh P-256 public key, kid kid.
func clientJWKS(t testing.TB, kid string) json.RawMessage {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub[1:33])
	y := base64.RawURLEncoding.EncodeToString(pub[33:])
	return json.RawMessage(fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q,"alg":"ES256","use":"sig"}]}`, x, y, kid))
}

// keyedClient is a client configuration NewRegisteredClient accepts,
// for client id.
func keyedClient(id fapi.ClientID) storage.RegisteredClientConfig {
	return storage.RegisteredClientConfig{ID: id, RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/cb"}, ClientAssertionAlgorithm: fapi.ES256}
}

// resolveKIDs is the kids ClientKeys' source resolves for client id's
// ES256 keys, or its error.
func resolveKIDs(source keys.ClientKeySource, id fapi.ClientID) ([]string, error) {
	set, err := source.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: id, Algorithm: fapi.ES256})
	if err != nil {
		return nil, err
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
	}
	return kids, nil
}

// ClientKeys keeps each client's keys to that client.
func TestClientKeysContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		keys.TestClientKeySourceContract(t, func(t *testing.T, clients map[fapi.ClientID][]byte) keys.ClientKeySource {
			d := freshDB(t, dialect)
			for id, jwks := range clients {
				must(t, d.Clients().PutWithKeys(context.Background(), keyedClient(id), sqlstore.ClientKeyRegistration{JWKS: jwks}))
			}
			source, err := d.ClientKeys(nil)
			must(t, err)
			return source
		})
	})
}

// A client registered, rekeyed or removed in the clients table while
// the server runs is served its current keys on the next request: the
// table is the one registry of clients and their keys.
func TestClientKeysFollowTheTable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		d := freshDB(t, dialect)
		source, err := d.ClientKeys(nil)
		must(t, err)
		repo := d.Clients()
		if _, err := resolveKIDs(source, "c"); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Fatalf("keys of an unregistered client = %v, want ErrNotFound", err)
		}

		must(t, repo.PutWithKeys(ctx, keyedClient("c"), sqlstore.ClientKeyRegistration{JWKS: clientJWKS(t, "k1")}))
		wantKIDs(t, source, "c", "k1")
		must(t, repo.PutWithKeys(ctx, keyedClient("c"), sqlstore.ClientKeyRegistration{JWKS: clientJWKS(t, "k2")}))
		wantKIDs(t, source, "c", "k2")

		must(t, repo.Put(ctx, keyedClient("c"))) // replaces the keys too
		wantKIDs(t, source, "c")

		_, err = repo.Delete(ctx, "c")
		must(t, err)
		if _, err := resolveKIDs(source, "c"); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Fatalf("keys of a deleted client = %v, want ErrNotFound", err)
		}
	})
}

// wantKIDs fails t unless source resolves exactly want for client id.
func wantKIDs(t *testing.T, source keys.ClientKeySource, id fapi.ClientID, want ...string) {
	t.Helper()
	got, err := resolveKIDs(source, id)
	if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("keys of %s = %v, %v, want %v", id, got, err, want)
	}
}

// A client registered with a jwks_uri is served the JWK Set published
// there, fetched through ClientKeys' fetcher.
func TestClientKeysFetchJWKSURI(t *testing.T) {
	jwks := clientJWKS(t, "published")
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(jwks)
	}))
	defer ts.Close()
	fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, AllowLoopbackHTTP: true})
	must(t, err)

	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		d := freshDB(t, dialect)
		must(t, d.Clients().PutWithKeys(context.Background(), keyedClient("c"), sqlstore.ClientKeyRegistration{JWKSURI: mustURL(t, ts.URL+"/jwks")}))
		source, err := d.ClientKeys(fetcher)
		must(t, err)
		wantKIDs(t, source, "c", "published")

		// Without a fetcher, nothing is fetched.
		noFetcher, err := d.ClientKeys(nil)
		must(t, err)
		if _, err := resolveKIDs(noFetcher, "c"); err == nil {
			t.Fatal("keys of a jwks_uri client without a fetcher = nil error, want an error")
		}
	})
}

// A key registration that can't serve keys is refused when written, and
// a row an operator wrote with one is an outage, never another client's
// keys or none.
func TestClientKeyRegistrationRefusals(t *testing.T) {
	jwks := clientJWKS(t, "k")
	uri := mustURL(t, "https://rp.example/jwks")
	for name, reg := range map[string]sqlstore.ClientKeyRegistration{
		"both":             {JWKSURI: uri, JWKS: jwks},
		"not an object":    {JWKS: json.RawMessage(`["keys"]`)},
		"not JSON":         {JWKS: json.RawMessage(`{"keys":`)},
		"no usable key":    {JWKS: json.RawMessage(`{"keys":[]}`)},
		"a private key":    {JWKS: json.RawMessage(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)},
		"duplicate member": {JWKS: json.RawMessage(strings.Replace(string(jwks), `"keys":`, `"keys":[],"keys":`, 1))},
	} {
		_, err := sqlstore.MarshalClientConfigWithKeys(keyedClient("c"), reg)
		if !errors.Is(err, sqlstore.ErrClientConfig) {
			t.Errorf("MarshalClientConfigWithKeys(%s) = %v, want ErrClientConfig", name, err)
		}
	}

	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migrated()
		_, db := p.open()
		if err := d.Clients().PutWithKeys(ctx, keyedClient("c"), sqlstore.ClientKeyRegistration{JWKSURI: uri, JWKS: jwks}); err == nil {
			t.Error("PutWithKeys(jwks_uri and jwks) = nil error, want an error")
		}
		source, err := d.ClientKeys(nil)
		must(t, err)
		for id, config := range map[string]string{
			"both":        `{"version":1,"redirect_uris":["https://rp.example/cb"],"jwks_uri":"https://rp.example/jwks","jwks":` + string(jwks) + `}`,
			"http uri":    `{"version":1,"redirect_uris":["https://rp.example/cb"],"jwks_uri":"http://rp.example/jwks"}`,
			"jwks array":  `{"version":1,"redirect_uris":["https://rp.example/cb"],"jwks":[]}`,
			"jwks case":   `{"version":1,"redirect_uris":["https://rp.example/cb"],"JWKS":` + string(jwks) + `}`,
			"unparseable": `{"version":1,"redirect_uri":"https://rp.example/cb"}`,
		} {
			rawExec(t, p, db, "INSERT INTO "+p.prefix+"clients (client_id, config) VALUES (?, ?)", id, config)
			_, err := resolveKIDs(source, fapi.ClientID(id))
			if !errors.Is(err, storage.ErrStoreUnavailable) || !errors.Is(err, sqlstore.ErrClientConfig) {
				t.Errorf("keys of a client row %s = %v, want ErrStoreUnavailable and ErrClientConfig", id, err)
			}
			if _, err := d.Clients().ResolveClient(ctx, fapi.ClientID(id)); !errors.Is(err, sqlstore.ErrClientConfig) {
				t.Errorf("ResolveClient(row %s) = %v, want ErrClientConfig", id, err)
			}
		}
	})
}

// A key registration survives MarshalClientConfigWithKeys and
// ParseClientKeys, beside the configuration, which ParseClientConfig
// still reads; a document without one registers no keys.
func TestClientKeyRegistrationRoundTrips(t *testing.T) {
	jwks := clientJWKS(t, "k")
	for name, reg := range map[string]sqlstore.ClientKeyRegistration{
		"jwks":     {JWKS: jwks},
		"jwks_uri": {JWKSURI: mustURL(t, "https://rp.example/jwks")},
		"neither":  {},
	} {
		doc, err := sqlstore.MarshalClientConfigWithKeys(fullClientConfig(t), reg)
		must(t, err)
		got, err := sqlstore.ParseClientKeys(doc)
		must(t, err)
		if got.JWKSURI != reg.JWKSURI || string(got.JWKS) != string(reg.JWKS) || got.IsZero() != (name == "neither") {
			t.Errorf("%s: ParseClientKeys(MarshalClientConfigWithKeys) = %+v, want %+v", name, got, reg)
		}
		cfg, err := sqlstore.ParseClientConfig("client-full", doc)
		must(t, err)
		if !reflect.DeepEqual(cfg, fullClientConfig(t)) {
			t.Errorf("%s: ParseClientConfig = %+v, want the configuration", name, cfg)
		}
	}
}
