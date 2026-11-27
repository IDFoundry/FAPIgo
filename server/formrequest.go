package server

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// maxFormRequestBytes bounds how much of an inbound request body
// FormRequestFromHTTP will read.
const maxFormRequestBytes = 1 << 20

// FormRequestFromHTTP builds a FormRequest faithfully from r's
// application/x-www-form-urlencoded body — preserving parameter order
// and every duplicate occurrence, rather than the collapsing net/http's
// own r.ParseForm/r.PostForm would apply, so this package (not the
// caller) detects duplicate or malformed parameters; see FormRequest's
// own doc comment for why that matters. This is an optional
// convenience for a caller that already uses net/http to serve these
// endpoints — nothing here is specific to any one deployment, so
// there's no reason for every adapter to reimplement it. A caller
// fronted by something other than net/http.Request is free to build a
// FormRequest by hand instead.
//
// A body it can't take — not form-encoded, unreadable, over 1 MiB, with
// more than 100 parameters, or malformed — is an invalid_request *Error
// (400), so WriteError answers it as the client's mistake, never a 500.
// Parameters are counted as the body is parsed, the way the server's
// methods count a FormRequest's (an empty pair, as in "a=1&&b=2", is
// none), and the 101st is refused before it is decoded: a body of many
// tiny parameters costs no more to refuse than one of a few. Every name
// and value is a copy, sharing no memory with the body, so keeping one
// (a client_id, say) doesn't keep the whole body alive. The same goes
// for the *FromHTTP constructors built on it
// (PushAuthorizationRequestFromHTTP, TokenEndpointRequestFromHTTP,
// BeginBackchannelAuthenticationRequestFromHTTP,
// TokenRevocationRequestFromHTTP, and BeginAuthorizationRequestFromHTTP
// for a POST).
//
// EndpointRoute is the route WithEndpointRoute marked r with, if any:
// see WithEndpointRoute.
func FormRequestFromHTTP(r *http.Request) (FormRequest, error) {
	// RFC 9110 §8.3.1: the media type is case-insensitive, and may carry
	// parameters ("; charset=UTF-8"); "application/x-www-form-urlencodedx"
	// is another type, not this one with a suffix.
	if ct := r.Header.Get("Content-Type"); !isFormContentType(ct) {
		return FormRequest{}, newError(ErrorInvalidRequest, http.StatusBadRequest, "the request body must be application/x-www-form-urlencoded", fmt.Errorf("content type %q", ct))
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFormRequestBytes+1))
	if err != nil {
		return FormRequest{}, newError(ErrorInvalidRequest, http.StatusBadRequest, "the request body could not be read", err)
	}
	if len(body) > maxFormRequestBytes {
		return FormRequest{}, newError(ErrorInvalidRequest, http.StatusBadRequest, "the request body is too large", fmt.Errorf("body exceeds %d bytes", maxFormRequestBytes))
	}

	params, err := decodeFormParameters(string(body), "the request body")
	if err != nil {
		return FormRequest{}, err
	}
	return FormRequest{Parameters: params, EndpointRoute: endpointRouteOf(r)}, nil
}

// decodeFormParameters decodes encoded — name=value pairs joined by
// "&", application/x-www-form-urlencoded — into its parameters, in
// order and with every repeat kept. Any error is an invalid_request
// *Error (400) whose description names encoded as subject ("the
// request body").
//
// An empty pair is skipped, as if it had never been sent, so the
// parameters are counted exactly as formParametersToMap counts them,
// and the one after maxFormParameters is refused before it is decoded.
// Neither skipping nor splitting off a pair allocates, so what a
// request costs beyond encoded itself is bounded by the parameters it
// may have, not by the pairs or separators it sends. Each name and
// value is a string of its own (unescapeFormComponent): a substring of
// encoded would keep all of it alive.
func decodeFormParameters(encoded, subject string) ([]FormParameter, error) {
	var params []FormParameter
	for rest := strings.TrimLeft(encoded, "&"); rest != ""; rest = strings.TrimLeft(rest, "&") {
		if len(params) == maxFormParameters {
			return nil, newError(ErrorInvalidRequest, http.StatusBadRequest, subject+" has too many parameters", fmt.Errorf("more than %d parameters", maxFormParameters))
		}
		var pair string
		pair, rest, _ = strings.Cut(rest, "&")
		name, value, _ := strings.Cut(pair, "=")
		decodedName, err := unescapeFormComponent(name)
		if err != nil {
			return nil, newError(ErrorInvalidRequest, http.StatusBadRequest, subject+" is malformed", fmt.Errorf("parameter name: %w", err))
		}
		decodedValue, err := unescapeFormComponent(value)
		if err != nil {
			return nil, newError(ErrorInvalidRequest, http.StatusBadRequest, subject+" is malformed", fmt.Errorf("parameter value: %w", err))
		}
		params = append(params, FormParameter{Name: decodedName, Value: decodedValue})
	}
	return params, nil
}

// unescapeFormComponent is url.QueryUnescape(s) in memory of its own,
// sharing none with s. QueryUnescape returns s itself when there is
// nothing to unescape (no "%" and no "+"), so such an s is copied
// instead; any other s it decodes into a new string, which isn't
// copied again.
func unescapeFormComponent(s string) (string, error) {
	if !strings.ContainsAny(s, "%+") {
		return strings.Clone(s), nil
	}
	return url.QueryUnescape(s)
}

// isFormContentType reports whether a Content-Type header names
// application/x-www-form-urlencoded, in any case, with or without
// parameters.
func isFormContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, "application/x-www-form-urlencoded")
}
