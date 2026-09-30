package checkout

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// Client IDs Alder Bank has registered.
const (
	tillClientID       fapi.ClientID = "harbour-coffee-till"
	pocketwiseClientID fapi.ClientID = "pocketwise"
)

// CIBA timings: short enough to watch in a demo.
const (
	requestLifetime = 3 * time.Minute
	pollInterval    = 2 * time.Second
)

// bank is Alder Bank's authorization server: it receives backchannel
// authentication requests, holds them until the customer decides on
// their phone, and issues tokens.
type bank struct {
	w   *World
	srv *server.Server
	// cfg and deps are what srv was built with, for the APIs' verifier
	// (serverresource.NewVerifier).
	cfg  server.Config
	deps server.Dependencies

	mu      sync.Mutex
	pending map[string]*pendingRequest // by auth_req_id
}

// pendingRequest is a request waiting for the customer on their phone.
type pendingRequest struct {
	authReqID   string
	handle      server.BackchannelAuthenticationHandle
	interaction server.BackchannelInteractionRequest
	customer    customer
	received    time.Time
	expires     time.Time
}

func (w *World) newBank(till, pocketwise clientKeys) (*bank, error) {
	endpoint := func(path string) (fapi.URL, error) { return fapi.ParseEndpointURL(w.URL(bankHost, path)) }
	issuer, err := fapi.ParseIssuerURL(w.URL(bankHost, ""))
	if err != nil {
		return nil, err
	}
	var endpoints server.Endpoints
	for _, e := range []struct {
		dst  *fapi.URL
		path string
	}{
		{&endpoints.Token, "/token"}, {&endpoints.JWKS, "/jwks"},
		{&endpoints.BackchannelAuthentication, "/backchannel-authentication"},
		// CIBA needs neither, but the server's metadata publishes both.
		{&endpoints.Authorization, "/authorize"}, {&endpoints.PushedAuthorizationRequest, "/par"},
	} {
		if *e.dst, err = endpoint(e.path); err != nil {
			return nil, err
		}
	}

	signer, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return nil, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.IDTokenSigning: signer, keys.AccessTokenSigning: signer},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.IDTokenSigning: fapi.ES256, keys.AccessTokenSigning: fapi.ES256},
		map[keys.SigningPurpose]string{keys.IDTokenSigning: "alder-1", keys.AccessTokenSigning: "alder-1"},
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
	clients, err := w.registeredClients()
	if err != nil {
		return nil, err
	}
	clientKeySource, err := ephemeral.NewClientKeySource(nil, []ephemeral.ClientKeySpec{
		{ClientID: tillClientID, JWKS: till.authJWKS},
		{ClientID: pocketwiseClientID, JWKS: pocketwise.authJWKS},
	})
	if err != nil {
		return nil, err
	}

	limits := server.RecommendedLimits()
	limits.BackchannelAuthenticationRequestLifetime = requestLifetime
	limits.MaxBackchannelAuthenticationRequestLifetime = 10 * time.Minute
	limits.BackchannelAuthenticationPollInterval = pollInterval
	algorithms := server.RecommendedAlgorithms()
	algorithms.BackchannelAuthenticationRequest = server.RecommendedAlgorithmSet()

	b := &bank{w: w, pending: map[string]*pendingRequest{}}
	b.cfg = server.Config{
		Issuer: issuer, Endpoints: endpoints, Profile: server.ProfileFAPISecurity,
		Algorithms: algorithms, Limits: limits, Assurance: server.AssuranceDevelopment,
		RAR: registry,
	}
	b.deps = server.Dependencies{
		Clients:                memstore.NewClientRepository(clients),
		Transactions:           memstore.NewTransactionStore(),
		Grants:                 memstore.NewGrantStore(),
		Replay:                 memstore.NewReplayStore(),
		ClientKeys:             clientKeySource,
		Keys:                   manager,
		AccessTokens:           accessTokens,
		Revocation:             memstore.NewRevocationStore(),
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  server.SystemClock{},
		Random:                 rand.Reader,
		Backchannel:            memstore.NewBackchannelAuthenticationStore(),
		BackchannelNotifier:    demoNotifier{client: w.net.Client(bankHost)},
		CIBARARPolicy: entitlements{
			tillClientID:       {paymentInitiationType.Type},
			pocketwiseClientID: {accountInformationType.Type},
		},
	}
	if b.srv, err = server.New(b.cfg, b.deps); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", b.discovery)
	mux.HandleFunc("GET /jwks", b.jwks)
	mux.HandleFunc("POST /backchannel-authentication", b.backchannelAuthentication)
	mux.HandleFunc("POST /token", b.token)
	w.router[bankHost] = mux
	return b, nil
}

// registeredClients is the two clients Alder Bank has onboarded: the
// till, which polls, and Pocketwise, which is pinged.
func (w *World) registeredClients() ([]storage.RegisteredClient, error) {
	notify, err := fapi.ParseEndpointURL(w.URL(pocketwiseHost, notifyPath))
	if err != nil {
		return nil, err
	}
	var out []storage.RegisteredClient
	for _, cfg := range []storage.RegisteredClientConfig{
		{
			ID: tillClientID, Display: storage.ClientDisplay{Name: "Harbour Coffee"},
			BackchannelTokenDeliveryMode: storage.BackchannelTokenDeliveryModePoll,
		},
		{
			ID: pocketwiseClientID, Display: storage.ClientDisplay{Name: "Pocketwise"},
			BackchannelTokenDeliveryMode:          storage.BackchannelTokenDeliveryModePing,
			BackchannelClientNotificationEndpoint: notify,
		},
	} {
		host := tillHost
		if cfg.ID == pocketwiseClientID {
			host = pocketwiseHost
		}
		// A CIBA client never receives a redirect, but every registered
		// client needs one.
		cfg.RedirectURIs = []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(w.URL(host, "/callback"))}
		cfg.ClientAuthMethod = storage.ClientAuthMethodPrivateKeyJWT
		cfg.ClientAssertionAlgorithm = fapi.ES256
		cfg.RequestObjectAlgorithm = fapi.ES256
		cfg.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
		cfg.SenderConstrain = storage.SenderConstrainDPoP
		cfg.AllowedScopes = []string{"openid"}
		c, err := storage.NewRegisteredClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("register %s: %w", cfg.ID, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func (b *bank) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.srv.Metadata(r.Context()))
}

func (b *bank) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := b.srv.PublicJWKS(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	set.WriteJSON(w)
}

// backchannelAuthentication is the CIBA endpoint. The server verifies
// the client, its signed request and the authorization_details against
// the client's entitlements; a request that passes waits here for the
// customer to decide on their phone.
func (b *bank) backchannelAuthentication(w http.ResponseWriter, r *http.Request) {
	req, err := server.BeginBackchannelAuthenticationRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	action, err := b.srv.BeginBackchannelAuthentication(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	switch a := action.(type) {
	case server.BackchannelAuthenticationLocalError:
		a.Error.WriteJSON(w)
	case server.BackchannelInteractionRequired:
		// The login hint is only a hint: it says whose phone to ask, and
		// the customer's approval there is what authenticates them.
		c, ok := customerByHint(string(a.Interaction.Hints.LoginHint))
		if !ok {
			// CIBA §13's unknown_user_id. The request was already stored,
			// so close it too.
			_ = b.srv.CompleteBackchannelAuthentication(r.Context(), server.CompleteBackchannelAuthenticationRequest{
				Handle: a.Handle, Result: server.Deny("unknown user"),
			})
			server.NewError("unknown_user_id", http.StatusBadRequest, "no Alder Bank customer matches that login hint").WriteJSON(w)
			return
		}
		now := time.Now()
		b.mu.Lock()
		b.pending[a.AuthReqID.String()] = &pendingRequest{
			authReqID: a.AuthReqID.String(), handle: a.Handle, interaction: a.Interaction,
			customer: c, received: now, expires: now.Add(a.ExpiresIn),
		}
		b.mu.Unlock()
		a.WriteJSON(w)
	}
}

func (b *bank) token(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	if req.GrantType() != "urn:openid:params:grant-type:ciba" {
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "only the CIBA grant is supported").WriteJSON(w)
		return
	}
	result, err := b.srv.ExchangeBackchannelAuthentication(r.Context(), req.BackchannelTokenExchange())
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// pendingFor is c's requests awaiting a decision, oldest first.
func (b *bank) pendingFor(c customer) []*pendingRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	var out []*pendingRequest
	for id, p := range b.pending {
		if now.After(p.expires) {
			delete(b.pending, id)
			continue
		}
		if p.customer.loginHint == c.loginHint {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].received.Before(out[j].received) })
	return out
}

// take removes and returns the pending request authReqID, if c owns it.
func (b *bank) take(c customer, authReqID string) (*pendingRequest, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[authReqID]
	if !ok || p.customer.loginHint != c.loginHint || time.Now().After(p.expires) {
		return nil, false
	}
	delete(b.pending, authReqID)
	return p, true
}

func (b *bank) lookup(c customer, authReqID string) (*pendingRequest, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[authReqID]
	if !ok || p.customer.loginHint != c.loginHint {
		return nil, false
	}
	return p, true
}

// decide records the customer's decision: approve with granted, or deny.
func (b *bank) decide(ctx context.Context, p *pendingRequest, approve bool, granted []json.RawMessage) error {
	result := server.Deny("the customer declined")
	if approve {
		subjectID, err := server.NewSubjectID(p.customer.loginHint)
		if err != nil {
			return err
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			return err
		}
		// The customer unlocked Alder Bank's app on their own phone.
		auth, err := server.NewAuthenticationContext(time.Now(), "urn:alder-bank:acr:app", []string{"user", "hwk"})
		if err != nil {
			return err
		}
		result = server.Authorize(subject, auth, server.GrantedAuthorization{
			Scope: p.interaction.Scope, AuthorizationDetails: granted,
		})
	}
	return b.srv.CompleteBackchannelAuthentication(ctx, server.CompleteBackchannelAuthenticationRequest{Handle: p.handle, Result: result})
}

// demoNotifier sends CIBA ping notifications (§10.2) through the demo
// network. A real deployment uses backchannelhttp.New, whose hardened
// client refuses loopback and private addresses; the demo's hosts are
// all loopback, reached through its own listener.
type demoNotifier struct{ client *http.Client }

func (n demoNotifier) Notify(ctx context.Context, notification server.BackchannelNotification) error {
	req, err := server.NewBackchannelNotificationRequest(ctx, notification)
	if err != nil {
		return err
	}
	res, err := n.client.Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	if res.StatusCode/100 != 2 {
		log.Printf("ping to %s: %s", notification.Endpoint, res.Status)
		return fmt.Errorf("notification endpoint answered %s", res.Status)
	}
	return nil
}

// paymentsOf is the payment_initiation details among values.
func paymentsOf(values extension.RARValues) []paymentInitiation {
	details, _ := extension.RARGet(values, paymentInitiationType)
	out := make([]paymentInitiation, len(details))
	for i, d := range details {
		out[i] = d.Fields
	}
	return out
}

// accountAccessOf is the account_information details among values.
func accountAccessOf(values extension.RARValues) []accountInformation {
	details, _ := extension.RARGet(values, accountInformationType)
	out := make([]accountInformation, len(details))
	for i, d := range details {
		out[i] = d.Fields
	}
	return out
}
