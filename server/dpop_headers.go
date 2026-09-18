package server

import "net/http"

// DPoPProofsFromHTTP returns every "DPoP" header value r carried, in
// receipt order — net/http's own r.Header.Values("DPoP"), which
// preserves duplicates deliberately: RFC 9449 §7.1 requires rejecting
// a request that carries more than one, a check every DPoPProofs field
// in this package (AuthorizationCodeExchangeRequest and its siblings)
// only gets right if the caller extracted headers this way. The more
// commonly reached-for r.Header.Get("DPoP") silently discards every
// value but the first instead, defeating that check without any
// symptom short of an actual multi-header attack. An optional
// convenience for a caller that already uses net/http, the same "no
// reason for every adapter to reimplement it" precedent as
// FormRequestFromHTTP/PeerCertificateFromHTTP.
func DPoPProofsFromHTTP(r *http.Request) []string {
	return r.Header.Values("DPoP")
}

// ClientAttestationHeadersFromHTTP returns every
// "OAuth-Client-Attestation" and "OAuth-Client-Attestation-PoP" header
// value r carried, in receipt order, for the same reason
// DPoPProofsFromHTTP exists: draft-ietf-oauth-attestation-based-client-auth-07
// §9 rule 1 requires exactly one of each, a check ClientAttestations/
// ClientAttestationPoPs (AuthorizationCodeExchangeRequest and its
// siblings) only gets right if the caller preserved duplicates via
// r.Header.Values(...) rather than collapsing them via r.Header.Get(...).
func ClientAttestationHeadersFromHTTP(r *http.Request) (attestations, pops []string) {
	return r.Header.Values("OAuth-Client-Attestation"), r.Header.Values("OAuth-Client-Attestation-PoP")
}
