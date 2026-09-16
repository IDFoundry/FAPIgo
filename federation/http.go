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
// This package offers no way to build a filtered listing itself — an
// embedder serving a federation_list_endpoint that can't honor any of
// these four filters against its own subordinate storage MUST call
// this before returning an unfiltered list, per §8.2's own requirement
// that an unsupported filter be rejected outright rather than silently
// ignored (a caller that asked for entity_type=openid_provider would
// otherwise get back RPs too, having no way to tell the filter was
// never applied). An embedder that can honor some or all of the four
// instead calls SubordinateListingFiltersFromRequest and applies the
// result itself — the two are independent, not sequenced; call
// whichever matches what the embedder's own storage can actually
// filter by.
func RejectUnsupportedListingFilters(r *http.Request) error {
	query := r.URL.Query()
	for _, name := range listingFilterParams {
		if query.Has(name) {
			return newError(ErrorUnsupportedParameter, http.StatusBadRequest, fmt.Sprintf("%q filtering is not supported", name), nil)
		}
	}
	return nil
}

// SubordinateListingFilters is the parsed, validated form of OpenID
// Federation 1.0 §8.2.1's four OPTIONAL Subordinate Listing filter
// query parameters, from SubordinateListingFiltersFromRequest. Every
// field's Go zero value ("this filter wasn't requested") already means
// "apply no filter of this kind", so a caller that skips
// SubordinateListingFiltersFromRequest entirely never needs to build
// one by hand.
//
// Matching this package's own "caller's own storage decides, this
// package only validates the request shape" division
// (RejectUnsupportedListingFilters, TrustMarkListingFilters,
// SubordinateStatementParams), this package builds no filtered listing
// itself — an embedder applies these fields against its own knowledge
// of its Immediate Subordinates' Entity Types, Trust Marks, and
// Intermediate status.
type SubordinateListingFilters struct {
	// EntityTypes is zero or more "entity_type" values. Per §8.2.1,
	// multiple values combine as a union, not an intersection ("the
	// result MUST be filtered to include all specified Entity Types"):
	// an embedder keeps an Immediate Subordinate whose own Entity Type
	// is any one of these, not only one that has every one of them.
	EntityTypes []string

	// TrustMarked is the "trust_marked" parameter's boolean value;
	// TrustMarkedSet is false when the parameter was absent (apply no
	// filter on it) and true when it was present, in which case
	// TrustMarked itself carries "true" or "false".
	TrustMarked, TrustMarkedSet bool

	// TrustMarkType is the "trust_mark_type" value, or "" when the
	// parameter was absent.
	TrustMarkType string

	// Intermediate is the "intermediate" parameter's boolean value;
	// IntermediateSet reports presence the same way TrustMarkedSet
	// does for TrustMarked.
	Intermediate, IntermediateSet bool
}

// SubordinateListingFiltersFromRequest extracts and validates OpenID
// Federation 1.0 §8.2.1's four OPTIONAL Subordinate Listing filter
// query parameters from r — entity_type (repeatable), trust_marked
// (boolean), trust_mark_type, and intermediate (boolean) — into a
// SubordinateListingFilters an embedder applies against its own
// subordinate storage. Returns a *Error (ErrorInvalidRequest, HTTP
// 400, ready to pass to WriteJSON) when trust_marked or intermediate
// is present but isn't literally "true" or "false" — §8.2.1 types both
// as Boolean, and this package accepts no other spelling of one.
//
// entity_type isn't validated as a recognized Entity Type Identifier:
// like ResolveRequestFromHTTP's own identically-shaped "entity_type"
// parameter, Entity Type Identifiers aren't a closed set this package
// could check against.
//
// Returning no error here doesn't mean an embedder can honor every
// filter present — see RejectUnsupportedListingFilters's own doc
// comment for how the two functions relate. An embedder that can
// honor only some of these four still returns ErrorUnsupportedParameter
// (via NewError) itself for whichever ones it can't.
func SubordinateListingFiltersFromRequest(r *http.Request) (SubordinateListingFilters, error) {
	query := r.URL.Query()

	filters := SubordinateListingFilters{
		EntityTypes:   query["entity_type"],
		TrustMarkType: query.Get("trust_mark_type"),
	}

	if raw := query.Get("trust_marked"); raw != "" {
		v, err := parseListingFilterBool("trust_marked", raw)
		if err != nil {
			return SubordinateListingFilters{}, err
		}
		filters.TrustMarked, filters.TrustMarkedSet = v, true
	}

	if raw := query.Get("intermediate"); raw != "" {
		v, err := parseListingFilterBool("intermediate", raw)
		if err != nil {
			return SubordinateListingFilters{}, err
		}
		filters.Intermediate, filters.IntermediateSet = v, true
	}

	return filters, nil
}

// TrustMarkRequestFromHTTP extracts and validates the query parameters
// of an OpenID Federation 1.0 §8.6.1 Trust Mark Request:
// "trust_mark_type" and "sub" — both REQUIRED here, unlike
// TrustMarkListingFilters' own "sub", which is OPTIONAL for that
// endpoint. Returns a *Error (ErrorInvalidRequest, HTTP 400, ready to
// pass to WriteJSON) when either is absent, or "sub" is not a valid
// Entity Identifier.
//
// Only GET requests with query parameters are supported — this
// package's own §8.6.1 text notes a client-authenticated request uses
// POST with the same parameters in the body instead (and MAY, at the
// endpoint's own choice, come from a requester other than the subject
// itself: "An example use case is to let a Federation Entity retrieve
// the Trust Mark for another Entity"), which this helper does not
// parse; an embedder needing that variant reads r.PostForm's own
// values directly.
//
// This package offers no way to look up whether subject actually has a
// trustMarkType Trust Mark — an embedder's own storage of issued Trust
// Marks answers that once these two values are known, the same
// "caller's own storage decides, this package only validates the
// request shape" division TrustMarkListingFilters and
// SubordinateListingFiltersFromRequest already establish. When it
// doesn't, build the §8.6.2-shaped 404 with
// NewError(ErrorNotFound, http.StatusNotFound, ...); when it does,
// TrustMarkIssuer.TrustMark's own returned token is the response body
// to serve, Content-Type TrustMarkContentType.
func TrustMarkRequestFromHTTP(r *http.Request) (trustMarkType, subject string, err error) {
	query := r.URL.Query()
	trustMarkType = query.Get("trust_mark_type")
	if trustMarkType == "" {
		return "", "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"trust_mark_type" is required`, nil)
	}
	subject = query.Get("sub")
	if subject == "" {
		return "", "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is required`, nil)
	}
	if verr := ValidEntityID(subject); verr != nil {
		return "", "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is not a valid Entity Identifier`, verr)
	}
	return trustMarkType, subject, nil
}

func parseListingFilterBool(name, raw string) (bool, error) {
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, newError(ErrorInvalidRequest, http.StatusBadRequest, fmt.Sprintf("%q must be \"true\" or \"false\"", name), nil)
	}
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
