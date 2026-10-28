package linked

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestAccountsRefusesAClientCredentialsToken: a client credentials token
// for a client whose client_id is a customer's username ("sam"), with
// account_access for that customer's account, reads nothing; the
// customer's own token for the same access reads the account.
func TestAccountsRefusesAClientCredentialsToken(t *testing.T) {
	w := testWorld(t)
	claims := func(grantType string) map[string]json.RawMessage {
		c := map[string]json.RawMessage{
			"authorization_details": json.RawMessage(`[{"type":"account_access","accounts":["XA21ALDR00001234567890"],"actions":["read_balances"]}]`),
		}
		if grantType != "" {
			c["grant_type"] = json.RawMessage(`"` + grantType + `"`)
		}
		return c
	}
	for name, tc := range map[string]struct {
		clientID, grantType string
		want                int
	}{
		"the customer's token":           {"pocketwise", "", http.StatusOK},
		"a client named as the customer": {"sam", "client_credentials", http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			w.api.accounts(rec, apiRequest(t, w, http.MethodGet, accountsPath, "", tc.clientID, "sam", claims(tc.grantType)))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
			if tc.want == http.StatusForbidden && strings.Contains(rec.Body.String(), "XA21") {
				t.Fatalf("the response carries the customer's account: %s", rec.Body)
			}
		})
	}
}

// testWorld is the demo, built without serving it: the tests call the
// API's handlers directly.
func testWorld(t *testing.T) *World {
	t.Helper()
	n, err := demokit.New("127.0.0.1:8443", Hosts(), "", "Test CA")
	if err != nil {
		t.Fatalf("demokit.New: %v", err)
	}
	w, err := New(8443, n)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

// apiRequest is a request to the API at path, presenting an access token
// the bank issued to clientID for subject, with claims, bound to a
// client certificate the request also carries.
func apiRequest(t *testing.T, w *World, method, path, body, clientID, subject string, claims map[string]json.RawMessage) *http.Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: clientID},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	issuer := w.bank.cfg.Issuer.String()
	token, _, err := w.bank.deps.AccessTokens.IssueAccessToken(context.Background(), server.AccessTokenParams{
		ClientID: fapi.ClientID(clientID), Subject: subject, Scope: []string{"accounts"},
		Thumbprint: base64.RawURLEncoding.EncodeToString(sum[:]), SenderConstrain: storage.SenderConstrainMTLS,
		Claims: claims, Issuer: issuer, Audience: issuer,
		Now: time.Now(), Lifetime: time.Minute, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	r := httptest.NewRequest(method, w.URL(apiHost, path), strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}
