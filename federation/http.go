package federation

import (
	"fmt"
	"net/http"
)

// listingFilterParams are OpenID Federation 1.0 §8.2's four OPTIONAL
// Subordinate Listing filter query parameters. A responder that doesn't
// support a given filter MUST reject a request naming it with
// unsupported_parameter (HTTP 400) rather than silently returning an
// unfiltered list — see RejectUnsupportedListingFilters.
var listingFilterParams = []string{"entity_type", "trust_marked", "trust_mark_type", "intermediate"}

// SubjectFromFetchRequest extracts and validates the "sub" query
// parameter from an OpenID Federation 1.0 §9 Fetch Subordinate
// Statement Request — REQUIRED, and (implicitly, since it names an
// Entity Identifier) syntactically valid. Returns a *Error
// (ErrorInvalidRequest, HTTP 400, ready to pass to WriteJSON) when
// absent or malformed.
//
// Only GET requests with "sub" as a query parameter are supported —
// this package's own §9 text notes client-authenticated fetch requests
// use POST with the parameter in the body instead, which this helper
// does not parse; an embedder needing that variant reads r.PostForm's
// own "sub" value directly.
//
// The one other case §9 separately calls out — "sub" naming the
// issuing entity itself — isn't checked here: only
// SubordinateIssueConfig.EntityID knows the issuer's own identity, so
// SubordinateIssuer.SubordinateStatement rejects that case instead.
func SubjectFromFetchRequest(r *http.Request) (string, error) {
	sub := r.URL.Query().Get("sub")
	if sub == "" {
		return "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is required`, nil)
	}
	if err := ValidEntityID(sub); err != nil {
		return "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is not a valid Entity Identifier`, err)
	}
	return sub, nil
}

// RejectUnsupportedListingFilters checks r for any of OpenID Federation
// 1.0 §8.2's four OPTIONAL Subordinate Listing filter parameters
// (entity_type, trust_marked, trust_mark_type, intermediate) and
// returns a *Error (ErrorUnsupportedParameter, HTTP 400, ready to pass
// to WriteJSON) naming the first one present, or nil if none are.
//
// This package offers no way to build a filtered listing — an embedder
// serving a federation_list_endpoint that only ever returns every known
// subordinate MUST call this before doing so, per §8.2's own
// requirement that an unsupported filter be rejected outright rather
// than silently ignored (a caller that asked for
// entity_type=openid_provider would otherwise get back RPs too, having
// no way to tell the filter was never applied).
func RejectUnsupportedListingFilters(r *http.Request) error {
	query := r.URL.Query()
	for _, name := range listingFilterParams {
		if query.Has(name) {
			return newError(ErrorUnsupportedParameter, http.StatusBadRequest, fmt.Sprintf("%q filtering is not supported", name), nil)
		}
	}
	return nil
}

// TrustMarkFromStatusRequest extracts and validates the "trust_mark"
// POST form parameter from an OpenID Federation 1.0 §8 Trust Mark
// Status Request — REQUIRED. Returns a *Error (ErrorInvalidRequest,
// HTTP 400, ready to pass to WriteJSON) when absent.
//
// Only the no-client-authentication shape (POST, parameters in the
// body) is covered — §8's client-authenticated variant is POST too, so
// r.PostFormValue already handles both; there is no GET variant to
// additionally support the way Fetch has one.
func TrustMarkFromStatusRequest(r *http.Request) (string, error) {
	trustMark := r.PostFormValue("trust_mark")
	if trustMark == "" {
		return "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"trust_mark" is required`, nil)
	}
	return trustMark, nil
}

// TrustMarkListingFilters extracts and validates the query parameters
// of an OpenID Federation 1.0 §9 Trust Marked Entities Listing Request:
// "trust_mark_type" (REQUIRED) and "sub" (OPTIONAL, validated as an
// Entity Identifier when present). Returns a *Error (ErrorInvalidRequest,
// HTTP 400, ready to pass to WriteJSON) when trust_mark_type is absent
// or sub is present but malformed.
//
// This package offers no way to build the actual filtered list — an
// embedder's own storage of issued Trust Marks answers the query once
// these two values are known, the same "caller's own storage decides,
// this package only validates the request shape" division
// RejectUnsupportedListingFilters and SubordinateStatementParams
// already establish.
func TrustMarkListingFilters(r *http.Request) (trustMarkType, subject string, err error) {
	query := r.URL.Query()
	trustMarkType = query.Get("trust_mark_type")
	if trustMarkType == "" {
		return "", "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"trust_mark_type" is required`, nil)
	}
	subject = query.Get("sub")
	if subject != "" {
		if err := ValidEntityID(subject); err != nil {
			return "", "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is not a valid Entity Identifier`, err)
		}
	}
	return trustMarkType, subject, nil
}
