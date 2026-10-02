package payment

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"github.com/idfoundry/fapigo/server/interactioncookie"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// shopClientID is the client ID Alder Bank registered Northgate
// Outfitters under.
const shopClientID fapi.ClientID = "northgate-outfitters"

const (
	bankKeyID      = "alder-1"
	approvalFailed = "Approval failed"
	authorizePath  = "/authorize"
)

// bank is Alder Bank's authorization server, with its own sign-in and
// consent pages.
type bank struct {
	w   *World
	srv *server.Server
	// cfg and deps are what srv was built with, for the API's verifier
	// (serverresource.NewVerifier).
	cfg  server.Config
	deps server.Dependencies
	// interaction carries the consent page's state in an encrypted
	// cookie: every instance would share its key.
	interaction *interactioncookie.Cookie
}

func (w *World) newBank(shop clientKeys) (*bank, error) {
	issuer, err := fapi.ParseIssuerURL(w.URL(bankHost, ""))
	if err != nil {
		return nil, err
	}
	var endpoints server.Endpoints
	for _, e := range []struct {
		dst  *fapi.URL
		path string
	}{
		{&endpoints.Authorization, authorizePath}, {&endpoints.PushedAuthorizationRequest, "/par"},
		{&endpoints.Token, "/token"}, {&endpoints.JWKS, "/jwks"},
	} {
		if *e.dst, err = fapi.ParseEndpointURL(w.URL(bankHost, e.path)); err != nil {
			return nil, err
		}
	}
	signer, err := ephemeral.GenerateSigner(fapi.ES256)
	if err != nil {
		return nil, err
	}
	manager, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.IDTokenSigning: signer, keys.AccessTokenSigning: signer, keys.JARMSigning: signer},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.IDTokenSigning: fapi.ES256, keys.AccessTokenSigning: fapi.ES256, keys.JARMSigning: fapi.ES256},
		map[keys.SigningPurpose]string{keys.IDTokenSigning: bankKeyID, keys.AccessTokenSigning: bankKeyID, keys.JARMSigning: bankKeyID},
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
	shopClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       shopClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(w.URL(shopHost, callbackPath))},
		ClientAuthMethod:         storage.ClientAuthMethodPrivateKeyJWT,
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		SenderConstrain:          storage.SenderConstrainDPoP,
		AllowedScopes:            []string{"openid"},
		// RFC 9396 §10: the shop may ask for payments, and nothing else.
		AuthorizationDetailsTypes: []string{paymentInitiationType.Type},
		Display:                   storage.ClientDisplay{Name: shopName},
	})
	if err != nil {
		return nil, err
	}
	clientKeySource, err := ephemeral.NewClientKeySource(nil, []ephemeral.ClientKeySpec{{ClientID: shopClientID, JWKS: shop.authJWKS}})
	if err != nil {
		return nil, err
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return nil, err
	}
	interaction, err := interactioncookie.New([][]byte{cookieKey}, interactioncookie.Options{})
	if err != nil {
		return nil, err
	}

	b := &bank{w: w, interaction: interaction}
	b.cfg = server.Config{
		Issuer: issuer, Endpoints: endpoints,
		// Message Signing: the shop's request must be a signed request
		// object, and the bank's response is signed too (JARM).
		Profile:    server.ProfileFAPISecurityWithMessageSigning,
		Algorithms: server.RecommendedAlgorithms(), Limits: server.RecommendedLimits(),
		Assurance: server.AssuranceDevelopment, RAR: registry,
	}
	b.deps = server.Dependencies{
		Clients:                memstore.NewClientRepository([]storage.RegisteredClient{shopClient}),
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
		// Each client's types are its registration's; no further rule.
		AuthorizationCodeRARPolicy: server.AllowRequestedAuthorizationDetails{},
	}
	if b.srv, err = server.New(b.cfg, b.deps); err != nil {
		return nil, err
	}
	// A registration naming a detail type the bank doesn't register (a
	// typo, say) fails here, not at the first request for it.
	if err := b.srv.CheckClientRegistration(shopClient); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", b.discovery)
	mux.HandleFunc("GET /jwks", b.jwks)
	mux.HandleFunc("POST /par", b.par)
	mux.HandleFunc("GET "+authorizePath, b.authorize)
	// The interaction cookie is SameSite, but a sibling *.localhost host
	// is the same site; refusing cross-origin POSTs is the CSRF defence
	// server.InteractionHandle's doc comment asks for.
	mux.Handle("POST "+authorizePath, http.NewCrossOriginProtection().Handler(http.HandlerFunc(b.decide)))
	mux.HandleFunc("POST /token", b.token)
	w.router[bankHost] = mux
	return b, nil
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
		server.WriteError(w, err)
		return
	}
	result, err := b.srv.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

func (b *bank) token(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	if req.GrantType() != "authorization_code" {
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "only authorization_code is supported").WriteJSON(w)
		return
	}
	result, err := b.srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// authorize starts the interaction and shows the sign-in and consent
// page. The interaction goes with the browser in a cookie the bank
// encrypts, so any instance of the bank can finish it, and the page's
// form carries the tag that ties it to this interaction.
func (b *bank) authorize(w http.ResponseWriter, r *http.Request) {
	// Local, never a redirect: an unreadable request names no
	// redirect URI it can be trusted with.
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Sign-in could not start", publicMessage(err, "The sign-in request is malformed."))
		return
	}
	action, err := b.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusInternalServerError, "Sign-in could not start", publicMessage(err, "Something went wrong. Please try again."))
		return
	}
	switch a := action.(type) {
	case server.InteractionRequired:
		tag, err := b.interaction.Set(w, a, time.Now())
		if err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, "Sign-in could not start", publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		b.w.render(w, "consent", b.consentPage(a.Interaction, tag, ""))
	case server.RedirectResponse:
		http.Redirect(w, r, a.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		b.w.renderError(w, bankHost, a.Error.HTTPStatus(), "Alder Bank refused the payment request", string(a.Error.Code())+": "+a.Error.PublicDescription())
	}
}

// consentView is one payment on the consent page. Payee is the name
// Alder Bank has on record for the account; CreditorName and Reference
// are only what the shop wrote.
type consentView struct {
	Amount, Payee, CreditorName, IBAN, Reference string
	PayeeVerified                                bool
}

func (b *bank) consentPage(in server.InteractionRequest, tag, problem string) consentPage {
	page := consentPage{Interaction: tag, Page: b.w.page("Alder Bank", bankHost), ClientName: in.ClientDisplay.Name, Problem: problem}
	if page.ClientName == "" {
		page.ClientName = string(in.ClientID)
	}
	for _, pay := range paymentsOf(in.AuthorizationDetails) {
		payee, verified := payees[pay.CreditorAccount.IBAN]
		page.Payments = append(page.Payments, consentView{
			Amount: "€" + pay.InstructedAmount.Amount, Payee: payee, PayeeVerified: verified,
			CreditorName: pay.CreditorName, IBAN: pay.CreditorAccount.IBAN, Reference: pay.RemittanceMessage,
		})
	}
	return page
}

// decide signs the customer in and records their decision. The payment
// is granted exactly as asked: the server refuses anything else.
func (b *bank) decide(w http.ResponseWriter, r *http.Request) {
	tag := r.PostFormValue(interactioncookie.FormField)
	handle, in, err := b.interaction.Read(r, time.Now(), tag)
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Session expired", "This browser has no payment approval in progress.")
		return
	}
	if err := r.ParseForm(); err != nil {
		b.w.renderError(w, bankHost, http.StatusBadRequest, "Malformed form", formUnreadable)
		return
	}
	result := server.Deny("the customer declined")
	if r.PostForm.Get("decision") == "approve" {
		c, ok := customerByName(r.PostForm.Get("username"))
		if !ok || !hmac.Equal([]byte(c.pin), []byte(r.PostForm.Get("pin"))) {
			b.w.render(w, "consent", b.consentPage(in, tag, "That username and PIN don't match."))
			return
		}
		var granted []json.RawMessage
		for _, pay := range paymentsOf(in.AuthorizationDetails) {
			raw, err := extension.RARSet(paymentInitiationType, pay)
			if err != nil {
				b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, "Something went wrong. Please try again."))
				return
			}
			granted = append(granted, raw)
		}
		subjectID, err := server.NewSubjectID(c.username)
		if err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		auth, err := server.NewAuthenticationContext(time.Now(), "urn:alder-bank:acr:pin", []string{"pin"})
		if err != nil {
			b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, "Something went wrong. Please try again."))
			return
		}
		result = server.Authorize(subject, auth, server.GrantedAuthorization{Scope: in.Scope, AuthorizationDetails: granted})
	}
	b.interaction.Clear(w)
	outcome, err := b.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		b.w.renderError(w, bankHost, http.StatusInternalServerError, approvalFailed, publicMessage(err, "Something went wrong. Please try again."))
		return
	}
	switch o := outcome.(type) {
	case server.AuthorizationRedirect:
		// The signed (JARM) response goes back to the shop.
		http.Redirect(w, r, o.Destination().String(), http.StatusFound)
	case server.AuthorizationLocalError:
		b.w.renderError(w, bankHost, o.Error.HTTPStatus(), approvalFailed, string(o.Error.Code())+": "+o.Error.PublicDescription())
	}
}
