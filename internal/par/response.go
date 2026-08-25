package par

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// maxResponseBytes bounds how large a PAR response body this package
// will attempt to parse.
const maxResponseBytes = 16 * 1024

// PushResult is a successful PAR response (RFC 9126 §2.2).
type PushResult struct {
	RequestURI string
	ExpiresIn  time.Duration
}

type rawPushResult struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// EncodeResult builds the JSON body of a successful PAR response.
func EncodeResult(r PushResult) ([]byte, error) {
	if r.RequestURI == "" {
		return nil, ErrMissingRequestURI
	}
	if r.ExpiresIn <= 0 {
		return nil, ErrInvalidExpiresIn
	}
	return json.Marshal(rawPushResult{
		RequestURI: r.RequestURI,
		ExpiresIn:  int64(r.ExpiresIn / time.Second),
	})
}

// DecodeResult parses the JSON body of a successful PAR response. It
// does not assume RequestURIPrefix — a third-party authorization server
// may use any opaque format for request_uri — and only requires that the
// value be present and that expires_in be a positive number of seconds.
// A member beyond request_uri/expires_in is tolerated, not rejected:
// RFC 9126 itself doesn't say so explicitly (it only ever defines
// request_uri/expires_in, with no extensibility clause either way),
// but rejecting a structurally-valid response just because a server
// added a field is the wrong default for a JSON API response — the
// same reasoning RFC 6749 §5.1 states outright for the token response.
func DecodeResult(body []byte) (PushResult, error) {
	if len(body) > maxResponseBytes {
		return PushResult{}, ErrResponseTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var raw rawPushResult
	if err := dec.Decode(&raw); err != nil {
		return PushResult{}, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	if raw.RequestURI == "" {
		return PushResult{}, ErrMissingRequestURI
	}
	if raw.ExpiresIn <= 0 {
		return PushResult{}, ErrInvalidExpiresIn
	}
	return PushResult{RequestURI: raw.RequestURI, ExpiresIn: time.Duration(raw.ExpiresIn) * time.Second}, nil
}

// ErrorResponse is a standard OAuth error response (RFC 6749 §5.2), used
// for a PAR endpoint's error responses.
type ErrorResponse struct {
	Code        string
	Description string // optional
	URI         string // optional
}

type rawErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// EncodeErrorResponse builds the JSON body of an OAuth error response.
func EncodeErrorResponse(e ErrorResponse) ([]byte, error) {
	if e.Code == "" {
		return nil, ErrMissingErrorCode
	}
	return json.Marshal(rawErrorResponse{
		Error:            e.Code,
		ErrorDescription: e.Description,
		ErrorURI:         e.URI,
	})
}

// DecodeErrorResponse parses the JSON body of an OAuth error response.
// A member beyond error/error_description/error_uri is tolerated, not
// rejected — RFC 6749 §5.2 defines this same closed set of fields but,
// like §5.1's success response, doesn't make an unrecognized extra one
// a reason to fail parsing the response at all.
func DecodeErrorResponse(body []byte) (ErrorResponse, error) {
	if len(body) > maxResponseBytes {
		return ErrorResponse{}, ErrResponseTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var raw rawErrorResponse
	if err := dec.Decode(&raw); err != nil {
		return ErrorResponse{}, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	if raw.Error == "" {
		return ErrorResponse{}, ErrMissingErrorCode
	}
	return ErrorResponse{Code: raw.Error, Description: raw.ErrorDescription, URI: raw.ErrorURI}, nil
}
