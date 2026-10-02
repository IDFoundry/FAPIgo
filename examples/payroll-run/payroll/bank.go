package payroll

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// The client IDs Alder Bank registered its two payroll providers under.
const (
	ledgerlineClientID  fapi.ClientID = "ledgerline"
	copperfieldClientID fapi.ClientID = "copperfield-payroll"
)

// Accounts at Alder Bank.
const (
	harbourIBAN     = "XA52ALDR00004242424242" // Harbour Coffee, Ledgerline's customer
	brightwaterIBAN = "XA19ALDR00005555666677" // Brightwater Bakery, Copperfield's customer
	// mandateLimit is the most one payroll batch may pay, in cents.
	mandateLimit = 25_000_00
)

var accountHolders = map[string]string{harbourIBAN: "Harbour Coffee", brightwaterIBAN: "Brightwater Bakery"}

const (
	bankKeyID    = "alder-1"
	payrollScope = "payroll"
)

// bank is Alder Bank's authorization server. It issues access tokens
// only through the client credentials grant, to clients authenticating
// with a certificate from its client CA, and binds each token to that
// certificate.
type bank struct {
	w   *World
	srv *server.Server
	// cfg and deps are what srv was built with, for the API's verifier
	// (serverresource.NewVerifier).
	cfg  server.Config
	deps server.Dependencies
}

func (w *World) newBank(certs certificates) (*bank, error) {
	issuer, err := fapi.ParseIssuerURL(w.URL(bankHost, ""))
	if err != nil {
		return nil, err
	}
	var endpoints server.Endpoints
	var aliases server.MTLSEndpoints
	for _, e := range []struct {
		dst        *fapi.URL
		host, path string
	}{
		{&endpoints.Authorization, bankHost, "/authorize"}, {&endpoints.PushedAuthorizationRequest, bankHost, "/par"},
		{&endpoints.Token, bankHost, "/token"}, {&endpoints.JWKS, bankHost, "/jwks"},
		// RFC 8705 §5: where a client with a certificate sends its token
		// requests. Only this host asks for one.
		{&aliases.Token, mtlsHost, "/token"},
	} {
		if *e.dst, err = fapi.ParseEndpointURL(w.URL(e.host, e.path)); err != nil {
			return nil, err
		}
	}
	signer, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return nil, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.AccessTokenSigning: signer},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		map[keys.SigningPurpose]string{keys.AccessTokenSigning: bankKeyID},
	)
	if err != nil {
		return nil, err
	}
	accessTokens, err := server.NewJWTAccessTokens(manager, fapi.ES256)
	if err != nil {
		return nil, err
	}
	registry, err := newRARRegistry()
	if err != nil {
		return nil, err
	}
	var clients []storage.RegisteredClient
	for _, c := range []struct {
		id      fapi.ClientID
		name    string
		subject string
	}{
		{ledgerlineClientID, "Ledgerline", certs.ledgerline.Leaf.Subject.String()},
		{copperfieldClientID, "Copperfield Payroll", certs.copperfield.Leaf.Subject.String()},
	} {
		client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID: c.id,
			// RFC 8705 §2.1.1: the client authenticates with a certificate
			// from a CA the bank trusts, whose subject is this one.
			ClientAuthMethod:  storage.ClientAuthMethodTLSClientAuth,
			ExpectedSubjectDN: c.subject,
			// RFC 8705 §3: its access tokens are bound to that certificate.
			SenderConstrain:              storage.SenderConstrainMTLS,
			AllowsClientCredentialsGrant: true,
			AllowedScopes:                []string{payrollScope},
			// RFC 9396 §10: payroll batches only; the mandates policy
			// then checks each batch against the company's mandate.
			AuthorizationDetailsTypes: []string{payrollBatchType.Type},
			Display:                   storage.ClientDisplay{Name: c.name},
		})
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	// No client signs anything: each authenticates with its certificate.
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	if err != nil {
		return nil, err
	}

	b := &bank{w: w}
	b.cfg = server.Config{
		Issuer: issuer, Endpoints: endpoints, MTLSEndpoints: aliases,
		Profile:    server.ProfileFAPISecurity,
		Algorithms: server.RecommendedAlgorithms(), Limits: server.RecommendedLimits(),
		Assurance: server.AssuranceDevelopment, RAR: registry,
		// No end user, so no ID tokens: plain OAuth, with the client
		// credentials grant switched on.
		OAuthOnly: true, ClientCredentialsGrant: true,
	}
	b.deps = server.Dependencies{
		Clients:      memstore.NewClientRepository(clients),
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       memstore.NewReplayStore(),
		ClientKeys:   clientKeys,
		Keys:         manager,
		AccessTokens: accessTokens,
		Revocation:   memstore.NewRevocationStore(),
		// The bank checks every client certificate itself: that it
		// chains to its root CA, and that neither the certificate nor the
		// issuing CA has been revoked. The issuing CAs go in
		// Intermediates, not Roots: a CA in Roots is a trust anchor,
		// which nothing checks for revocation, so the retired CA would
		// go on being trusted after the root revoked it.
		ClientCertificateTrust: server.TrustedClientCAs{
			Roots:         w.rootCA.pool,
			Intermediates: intermediates(w.clientCA, w.retiredCA),
			Revocation:    server.ClientCertificateCRLs{Lists: w.currentCRLs},
		},
		Clock:  server.SystemClock{},
		Random: rand.Reader,
		ClientCredentialsRARPolicy: mandates{
			ledgerlineClientID:  {{Account: harbourIBAN, Limit: mandateLimit}},
			copperfieldClientID: {{Account: brightwaterIBAN, Limit: mandateLimit}},
		},
	}
	if b.srv, err = server.New(b.cfg, b.deps); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", b.discovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", b.discovery)
	mux.HandleFunc("GET /jwks", b.jwks)
	// The bank's redirect-based flow: neither payroll provider has a
	// redirect URI, so both refuse them.
	mux.HandleFunc("POST /par", b.par)
	mux.HandleFunc("GET /authorize", b.authorize)
	// Served at both hosts, but only mtls.bank.localhost asks for a
	// certificate: a token request without one fails client
	// authentication.
	mux.HandleFunc("POST /token", b.token)
	w.router[bankHost] = mux
	mtls := http.NewServeMux()
	mtls.HandleFunc("POST /token", b.token)
	w.router[mtlsHost] = mtls
	return b, nil
}

// intermediates is a pool of the issuing CAs' certificates.
func intermediates(cas ...*pki) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, ca := range cas {
		pool.AddCert(ca.ca)
	}
	return pool
}

func (b *bank) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.srv.Metadata(r.Context()))
}

func (b *bank) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := b.srv.PublicJWKS(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	set.WriteJSON(w)
}

func (b *bank) par(w http.ResponseWriter, r *http.Request) {
	req, err := server.PushAuthorizationRequestFromHTTP(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	result, err := b.srv.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

func (b *bank) authorize(w http.ResponseWriter, r *http.Request) {
	// Local, never a redirect: an unreadable request names no
	// redirect URI it can be trusted with.
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		http.Error(w, publicMessage(err, "The authorization request is malformed."), http.StatusBadRequest)
		return
	}
	action, err := b.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		http.Error(w, publicMessage(err, "The authorization request is invalid."), http.StatusBadRequest)
		return
	}
	switch a := action.(type) {
	case server.RedirectResponse:
		http.Redirect(w, r, a.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		a.Error.WriteJSON(w)
	default:
		// Only reachable for a client with a redirect URI, which none
		// has: there are no sign-in pages here.
		http.Error(w, "Alder Bank's sign-in isn't part of this demo", http.StatusNotFound)
	}
}

func (b *bank) token(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	if req.GrantType() != "client_credentials" {
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "only client_credentials is supported").WriteJSON(w)
		return
	}
	// The request carries the certificate presented on its TLS
	// connection (PeerCertificateFromHTTP): the server authenticates the
	// client with it and binds the token to it.
	result, err := b.srv.RequestClientCredentialsToken(r.Context(), req.ClientCredentials())
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}
