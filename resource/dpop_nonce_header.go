package resource

import "net/http"

// SetDPoPNonce sets h's DPoP-Nonce header to a.NextDPoPNonce, when Verify
// issued one, so the client's next request already carries a valid
// nonce (RFC 9449 §8). Call it on every successful response:
//
//	authz, err := verifier.Verify(ctx, resource.VerifyRequestFromHTTP(r, target))
//	// ...
//	authz.SetDPoPNonce(w.Header())
func (a AuthorizationContext) SetDPoPNonce(h http.Header) {
	if a.NextDPoPNonce != "" {
		h.Set("DPoP-Nonce", a.NextDPoPNonce)
	}
}
