package client

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/idfoundry/fapigo/internal/authchallenge"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/storage"
)

// ServerErrorResponse is an error response received from the
// authorization server — RFC 6749 §5.2, from the pushed authorization
// request, token and backchannel authentication endpoints — or from the
// UserInfo endpoint, where Code, Description and URI come from the
// WWW-Authenticate challenge (RFC 6750 §3, RFC 9449 §7.1) or, when that
// carries no error, from an RFC 6749 §5.2-style JSON body.
//
// Code, Description and URI are each empty when the server sent none,
// or sent one containing characters RFC 6749 §5.2 doesn't allow; a
// response that wasn't an OAuth error at all (an HTML 502 page, say)
// still carries HTTPStatus. Description is the server's own text: show
// it to an operator, not as a user-facing message.
//
// Whether a failed call is worth retrying depends on the call, not only
// on Code. A pushed authorization request, a client credentials request
// or a backchannel authentication request can simply be made again.
// ExchangeCode can't: after a server_error the authorization server may
// already have consumed the authorization code, so a retry typically
// fails with invalid_grant, and the flow should restart with
// BeginAuthorization.
type ServerErrorResponse struct {
	Code        string // "error", e.g. "invalid_client"
	Description string // "error_description"
	URI         string // "error_uri"
	HTTPStatus  int
}

// ServerResponse returns the server's error response, when this Error
// was caused by one. It returns false for errors raised before a
// response arrived (transport failures) or by this client's own
// validation of a successful response.
func (e *Error) ServerResponse() (ServerErrorResponse, bool) {
	if e.server == nil {
		return ServerErrorResponse{}, false
	}
	return *e.server, true
}

func (e *Error) withServerResponse(r ServerErrorResponse) *Error {
	e.server = &r
	return e
}

// newServerErrorResponse keeps each field only if it is within RFC 6749
// §5.2's character set, so nothing a server sends reaches a caller's UI
// or logs with control characters, quotes or non-ASCII bytes in it.
func newServerErrorResponse(status int, code, description, uri string) ServerErrorResponse {
	r := ServerErrorResponse{HTTPStatus: status}
	if isErrorText(code) {
		r.Code = code
	}
	if isErrorText(description) {
		r.Description = description
	}
	if isErrorURI(uri) {
		r.URI = uri
	}
	return r
}

// parErrorFromResponse maps a non-success pushed authorization request,
// token or backchannel authentication HTTP response to a typed Error,
// falling back to a generic message if the body isn't a well-formed
// OAuth error response.
func parErrorFromResponse(status int, body []byte) *Error {
	errResp, err := par.DecodeErrorResponse(body)
	if err != nil {
		return newError(ErrorInvalidResponse, "authorization server returned an error", fmt.Errorf("status body: %s", strconv.Quote(string(body)))).
			withServerResponse(ServerErrorResponse{HTTPStatus: status})
	}
	resp := newServerErrorResponse(status, errResp.Code, errResp.Description, errResp.URI)
	code := errResp.Code
	if resp.Code == "" {
		code = strconv.Quote(code)
	}
	return newError(ErrorInvalidResponse, resp.Description, fmt.Errorf("authorization server error: %s", code)).
		withServerResponse(resp)
}

// resourceErrorResponse reads a protected resource's error response:
// the challenge for the scheme this client authenticated with, or,
// when that carries no error, an RFC 6749 §5.2-style JSON body.
func (c *Client) resourceErrorResponse(res *http.Response, body []byte) ServerErrorResponse {
	scheme := "DPoP"
	if c.cfg.SenderConstrain == storage.SenderConstrainMTLS {
		scheme = "Bearer"
	}
	challenge, ok, err := authchallenge.Find(res.Header.Values("WWW-Authenticate"), scheme)
	if err == nil && ok && challenge.Params["error"] != "" {
		return newServerErrorResponse(res.StatusCode, challenge.Params["error"], challenge.Params["error_description"], challenge.Params["error_uri"])
	}
	if errResp, err := par.DecodeErrorResponse(body); err == nil {
		return newServerErrorResponse(res.StatusCode, errResp.Code, errResp.Description, errResp.URI)
	}
	return ServerErrorResponse{HTTPStatus: res.StatusCode}
}

// isErrorText reports whether s is 1*NQSCHAR, the grammar RFC 6749
// §5.2 (and RFC 6750 §3) gives "error" and "error_description":
// %x20-21 / %x23-5B / %x5D-7E.
func isErrorText(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x22 || c == 0x5C || c > 0x7E {
			return false
		}
	}
	return true
}

// isErrorURI reports whether s is within RFC 6749 §5.2's "error_uri"
// character set: %x21 / %x23-5B / %x5D-7E.
func isErrorURI(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x22 || c == 0x5C || c > 0x7E {
			return false
		}
	}
	return true
}
