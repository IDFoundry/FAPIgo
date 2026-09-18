package resource

import "net/http"

// DPoPProofsFromHTTP returns every "DPoP" header value r carried, in
// receipt order — net/http's own r.Header.Values("DPoP"), which
// preserves duplicates deliberately: RFC 9449 §7.1 requires rejecting
// a request that carries more than one, a check VerifyRequest.DPoPProofs'
// own doc comment only holds if the caller extracted headers this way.
// The more commonly reached-for r.Header.Get("DPoP") silently discards
// every value but the first instead, defeating that check without any
// symptom short of an actual multi-header attack. An optional
// convenience for a caller that already uses net/http, the same "no
// reason for every adapter to reimplement it" precedent as
// PeerCertificateFromHTTP.
func DPoPProofsFromHTTP(r *http.Request) []string {
	return r.Header.Values("DPoP")
}
