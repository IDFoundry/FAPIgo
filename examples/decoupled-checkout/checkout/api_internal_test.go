package checkout

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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/examples/internal/demokit"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// failingReplayStore can't record anything.
type failingReplayStore struct{}

func (failingReplayStore) UseOnce(context.Context, storage.ReplayUse) error {
	return errors.New("replay store unavailable")
}

// approvalToken is an access token from the grant codeGrantID names.
func approvalToken(key, codeGrantID string) resource.AuthorizationContext {
	return resource.AuthorizationContext{
		Key: key, ExpiresAt: time.Now().Add(time.Minute),
		Claims: map[string]json.RawMessage{"code_grant_id": json.RawMessage(`"` + codeGrantID + `"`)},
	}
}

// TestApprovalUsedOnceAcrossInstances covers two instances of the API
// sharing the bank's replay store: whichever sees an approval second
// refuses it, and a store that can't be reached refuses too.
func TestApprovalUsedOnceAcrossInstances(t *testing.T) {
	shared := memstore.NewReplayStore()
	first, second := &api{replay: shared, grantLifetime: time.Hour}, &api{replay: shared, grantLifetime: time.Hour}
	authz := approvalToken("token-1", "grant-1")
	if !first.useOnce(context.Background(), authz) {
		t.Fatal("first use refused")
	}
	if second.useOnce(context.Background(), authz) {
		t.Error("the same approval was used again on another instance")
	}
	if !second.useOnce(context.Background(), approvalToken("token-2", "grant-2")) {
		t.Error("another approval was refused")
	}
	if (&api{replay: failingReplayStore{}}).useOnce(context.Background(), approvalToken("token-3", "grant-3")) {
		t.Error("an unreachable replay store allowed the approval")
	}
}

// TestApprovalUsedOnceAcrossRefresh: a refreshed access token has a new
// Key but carries the same approval, so it can't be used again; and a
// token naming no grant is refused outright.
func TestApprovalUsedOnceAcrossRefresh(t *testing.T) {
	a := &api{replay: memstore.NewReplayStore(), grantLifetime: time.Hour}
	if !a.useOnce(context.Background(), approvalToken("token-1", "grant-1")) {
		t.Fatal("first use refused")
	}
	if a.useOnce(context.Background(), approvalToken("token-1-refreshed", "grant-1")) {
		t.Error("a refreshed token used the same approval again")
	}
	if a.useOnce(context.Background(), resource.AuthorizationContext{Key: "token-4", ExpiresAt: time.Now().Add(time.Minute)}) {
		t.Error("a token naming no grant was allowed")
	}
}

// TestAPIRefusesAClientCredentialsToken: a client credentials token for
// a client whose client_id is a customer's login hint ("sam"), carrying
// approved details for that customer's account, neither pays nor reads;
// the customer's own token for the same details does both. The client's
// payment token even names a grant, so the replay check alone wouldn't
// stop it.
func TestAPIRefusesAClientCredentialsToken(t *testing.T) {
	w := testWorld(t)
	const order = `{"instructedAmount":{"currency":"EUR","amount":"42.50"},"creditorAccount":{"iban":"XA55ALDR00004242424242"}}`
	payment := json.RawMessage(`[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"42.50"},"creditorName":"Till","creditorAccount":{"iban":"XA55ALDR00004242424242"}}]`)
	reading := json.RawMessage(`[{"type":"account_information","actions":["read_balances"],"accounts":[{"iban":"XA21ALDR00001234567890"}]}]`)
	for name, tc := range map[string]struct {
		clientID, grantType string
		want                int
	}{
		"the customer's token":           {"till", "", http.StatusOK},
		"a client named as the customer": {"sam", "client_credentials", http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			pay := apiRequest(t, w, http.MethodPost, paymentsPath, order, testToken{tc.clientID, "sam", testClaims(tc.grantType, payment, "grant-"+tc.clientID)})
			assertAPIStatus(t, w, pay, tc.want)
			read := apiRequest(t, w, http.MethodGet, accountsPath+"XA21ALDR00001234567890/balances", "", testToken{tc.clientID, "sam", testClaims(tc.grantType, reading, "")})
			assertAPIStatus(t, w, read, tc.want)
		})
	}
}

// testClaims are an access token's claims: details as its
// authorization_details, and grantType and codeGrantID when they're set.
func testClaims(grantType string, details json.RawMessage, codeGrantID string) map[string]json.RawMessage {
	c := map[string]json.RawMessage{"authorization_details": details}
	if grantType != "" {
		c["grant_type"] = json.RawMessage(`"` + grantType + `"`)
	}
	if codeGrantID != "" {
		c["code_grant_id"] = json.RawMessage(`"` + codeGrantID + `"`)
	}
	return c
}

// assertAPIStatus serves r through the demo's router and checks its
// status.
func assertAPIStatus(t *testing.T, w *World, r *http.Request, want int) {
	t.Helper()
	rec := httptest.NewRecorder()
	w.Handler().ServeHTTP(rec, r)
	if rec.Code != want {
		t.Fatalf("%s %s: status = %d, want %d: %s", r.Method, r.URL.Path, rec.Code, want, rec.Body)
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

// testToken is an access token for apiRequest: issued to clientID for
// subject, with claims.
type testToken struct {
	clientID, subject string
	claims            map[string]json.RawMessage
}

// apiRequest is a request to the API at path, presenting tok, as the bank
// issues it, bound to a client certificate the request also carries.
func apiRequest(t *testing.T, w *World, method, path, body string, tok testToken) *http.Request {
	t.Helper()
	clientID, subject, claims := tok.clientID, tok.subject, tok.claims
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
