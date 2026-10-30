package sqlstore_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

func mustURL(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// fullClientConfig sets every field the configuration document carries
// to something other than its zero value, in a combination
// NewRegisteredClient accepts.
func fullClientConfig(t *testing.T) storage.RegisteredClientConfig {
	t.Helper()
	return storage.RegisteredClientConfig{
		ID:                                        "client-full",
		RedirectURIs:                              []fapi.RegisteredRedirectURI{"https://rp.example/cb", "https://rp.example/cb2"},
		ApplicationType:                           storage.ApplicationTypeWeb,
		ClientAuthMethods:                         []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT, storage.ClientAuthMethodSelfSignedTLSClientAuth},
		ClientAssertionAlgorithms:                 []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256},
		ExpectedCertificateThumbprint:             "x5t-1",
		AdditionalCertificateThumbprints:          []string{"x5t-2"},
		RequestObjectAlgorithm:                    fapi.ES256,
		SenderConstrain:                           storage.SenderConstrainMTLS,
		IDTokenEncryptionKeyManagement:            fapi.RSAOAEP256,
		IDTokenEncryptionContentEncryption:        fapi.A256GCM,
		UserInfoEncryptionKeyManagement:           fapi.ECDHESA256KW,
		UserInfoEncryptionContentEncryption:       fapi.A256CBCHS512,
		BackchannelAuthenticationRequestAlgorithm: fapi.PS256,
		BackchannelTokenDeliveryMode:              storage.BackchannelTokenDeliveryModePing,
		BackchannelClientNotificationEndpoint:     mustURL(t, "https://rp.example/ciba"),
		AllowedScopes:                             []string{"openid", "accounts"},
		AuthorizationDetailsTypes:                 []string{"payment_initiation"},
		AllowedResources:                          []string{"https://rs.example/"},
		AllowsClientCredentialsGrant:              true,
		Display: storage.ClientDisplay{
			Name: "Example RP", LogoURI: mustURL(t, "https://rp.example/logo.png"),
			PolicyURI: mustURL(t, "https://rp.example/policy"), TermsOfServiceURI: mustURL(t, "https://rp.example/tos"),
		},
		SubjectType: fapi.SubjectTypePairwise,
		Sector:      "rp.example",
	}
}

// Every field survives MarshalClientConfig and ParseClientConfig, and
// Put and ResolveClient.
func TestClientConfigRoundTrips(t *testing.T) {
	cfg := fullClientConfig(t)
	if _, err := storage.NewRegisteredClient(cfg); err != nil {
		t.Fatalf("fixture: NewRegisteredClient: %v", err)
	}
	data, err := sqlstore.MarshalClientConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sqlstore.ParseClientConfig(cfg.ID, data)
	if err != nil {
		t.Fatalf("ParseClientConfig(%s): %v", data, err)
	}
	if !reflect.DeepEqual(got, cfg) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, cfg)
	}
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		repo := freshDB(t, dialect).Clients()
		if err := repo.Put(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		c, err := repo.ResolveClient(context.Background(), cfg.ID)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := storage.NewRegisteredClient(cfg)
		if !reflect.DeepEqual(c, want) {
			t.Fatalf("ResolveClient = %+v, want %+v", c, want)
		}
	})
}

// A minimal client is a short document, its zero-valued fields
// omitted, and the zero values that mean something (private_key_jwt,
// DPoP, web, poll) come back.
func TestClientConfigOmitsZeroValues(t *testing.T) {
	cfg := storage.RegisteredClientConfig{
		ID:                       "client-1",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/cb"},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"accounts"},
	}
	data, err := sqlstore.MarshalClientConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":1,"redirect_uris":["https://rp.example/cb"],"client_assertion_algorithm":"ES256","allowed_scopes":["accounts"]}`
	if string(data) != want {
		t.Fatalf("MarshalClientConfig = %s, want %s", data, want)
	}
	got, err := sqlstore.ParseClientConfig(cfg.ID, data)
	if err != nil || !reflect.DeepEqual(got, cfg) {
		t.Fatalf("ParseClientConfig = %+v, %v, want %+v", got, err, cfg)
	}
}

func TestMarshalClientConfigRefusesFederationClient(t *testing.T) {
	cfg := storage.RegisteredClientConfig{ID: "c", AutomaticFederationRegistration: true}
	if _, err := sqlstore.MarshalClientConfig(cfg); !errors.Is(err, sqlstore.ErrClientConfig) {
		t.Fatalf("MarshalClientConfig(AutomaticFederationRegistration) = %v, want ErrClientConfig", err)
	}
}

func TestParseClientConfigRefusals(t *testing.T) {
	for name, doc := range map[string]string{
		"not JSON":              `{`,
		"null":                  `null`,
		"array":                 `[]`,
		"no version":            `{"allowed_scopes":["a"]}`,
		"version 2":             `{"version":2}`,
		"unknown member":        `{"version":1,"allowed_scope":["a"]}`,
		"federation member":     `{"version":1,"automatic_federation_registration":true}`,
		"client_id member":      `{"version":1,"client_id":"other"}`,
		"trailing document":     `{"version":1} {"version":1}`,
		"wrong type":            `{"version":1,"allowed_scopes":"a"}`,
		"unknown auth method":   `{"version":1,"client_auth_method":"client_secret_basic"}`,
		"empty list value":      `{"version":1,"client_auth_methods":["private_key_jwt",""]}`,
		"unknown algorithm":     `{"version":1,"client_assertion_algorithm":"RS256"}`,
		"lower-case algorithm":  `{"version":1,"request_object_algorithm":"es256"}`,
		"unknown sender":        `{"version":1,"sender_constrain":"bearer"}`,
		"unknown app type":      `{"version":1,"application_type":"desktop"}`,
		"unknown delivery mode": `{"version":1,"backchannel_token_delivery_mode":"push"}`,
		"unknown subject type":  `{"version":1,"subject_type":"Public"}`,
		"unknown key mgmt":      `{"version":1,"id_token_encryption_key_management":"RSA1_5"}`,
		"unknown content enc":   `{"version":1,"userinfo_encryption_content_encryption":"A128GCM"}`,
		"http endpoint":         `{"version":1,"backchannel_client_notification_endpoint":"http://rp.example/ciba"}`,
		"javascript logo":       `{"version":1,"display":{"logo_uri":"javascript:alert(1)"}}`,
		"unknown display":       `{"version":1,"display":{"title":"x"}}`,
	} {
		if _, err := sqlstore.ParseClientConfig("c", []byte(doc)); !errors.Is(err, sqlstore.ErrClientConfig) {
			t.Errorf("%s: ParseClientConfig(%s) = %v, want ErrClientConfig", name, doc, err)
		}
	}
}

// A row the operator got wrong is an outage, answered 500, not an
// unknown client; one with a valid document NewRegisteredClient
// refuses likewise.
func TestResolveClientWithBadRowIsUnavailable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migrated()
		_, db := p.open()
		for id, config := range map[string]string{
			"unparsable": `{"version":1,"redirect_uri":"https://rp.example/cb"}`,
			"invalid":    `{"version":1,"redirect_uris":["http://rp.example/cb"]}`,
		} {
			insert := "INSERT INTO " + p.prefix + "clients (client_id, config) VALUES ($1, $2)"
			if dialect == sqlstore.SQLite {
				insert = strings.NewReplacer("$1", "?", "$2", "?").Replace(insert)
			}
			if _, err := db.ExecContext(ctx, insert, id, config); err != nil {
				t.Fatal(err)
			}
			_, err := d.Clients().ResolveClient(ctx, fapi.ClientID(id))
			if !errors.Is(err, storage.ErrStoreUnavailable) || !errors.Is(err, sqlstore.ErrClientConfig) {
				t.Errorf("ResolveClient(%s) = %v, want ErrStoreUnavailable and ErrClientConfig", id, err)
			}
		}
	})
}

func TestClientRepositoryPutAndDelete(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		repo := freshDB(t, dialect).Clients()
		if err := repo.Put(ctx, storage.RegisteredClientConfig{ID: "bad", RedirectURIs: []fapi.RegisteredRedirectURI{"http://rp.example/cb"}}); err == nil {
			t.Error("Put of a configuration NewRegisteredClient refuses = nil error, want an error")
		}
		cfg := storage.RegisteredClientConfig{ID: "c", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/cb"}, ClientAssertionAlgorithm: fapi.ES256}
		must(t, repo.Put(ctx, cfg))
		cfg.AllowedScopes = []string{"accounts"}
		must(t, repo.Put(ctx, cfg)) // replaces
		c, err := repo.ResolveClient(ctx, "c")
		if err != nil || !c.AllowsScope("accounts") {
			t.Fatalf("ResolveClient after replacing Put = %v, %v, want the replacement", c, err)
		}
		if deleted, err := repo.Delete(ctx, "c"); err != nil || !deleted {
			t.Fatalf("Delete = %v, %v, want true, nil", deleted, err)
		}
		if deleted, err := repo.Delete(ctx, "c"); err != nil || deleted {
			t.Fatalf("Delete again = %v, %v, want false, nil", deleted, err)
		}
		if _, err := repo.ResolveClient(ctx, "c"); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Fatalf("ResolveClient after Delete = %v, want ErrNotFound", err)
		}
	})
}

// The package documentation's example document is a valid client.
func TestDocumentedClientConfigParses(t *testing.T) {
	const doc = `{"version":1,
 "redirect_uris":["https://rp.example/callback"],
 "client_assertion_algorithm":"ES256",
 "sender_constrain":"dpop",
 "allowed_scopes":["openid","accounts"]}`
	cfg, err := sqlstore.ParseClientConfig("client-1", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.NewRegisteredClient(cfg); err != nil {
		t.Fatal(err)
	}
}
