package fapitest

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/osanderson/go-fapi/server"
)

// maxFormBytes bounds how much of an inbound request body this adapter
// will read.
const maxFormBytes = 1 << 20

// formRequestFromHTTP builds a server.FormRequest faithfully from r's
// application/x-www-form-urlencoded body — preserving parameter order
// and every duplicate occurrence, rather than the collapsing net/http's
// own r.ParseForm/r.PostForm would apply — the adapter role
// ARCHITECTURE.md design rule 7 assigns to fapihttp "or an equivalent
// adapter"; fapitest provides it here for the server side, since
// fapihttp itself is a client-side fetch client.
func formRequestFromHTTP(r *http.Request) (server.FormRequest, error) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return server.FormRequest{}, fmt.Errorf("fapitest: unexpected content type %q", ct)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFormBytes+1))
	if err != nil {
		return server.FormRequest{}, fmt.Errorf("fapitest: read body: %w", err)
	}
	if len(body) > maxFormBytes {
		return server.FormRequest{}, fmt.Errorf("fapitest: body exceeds %d bytes", maxFormBytes)
	}

	var params []server.FormParameter
	for _, pair := range strings.Split(string(body), "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			return server.FormRequest{}, fmt.Errorf("fapitest: malformed parameter name: %w", err)
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return server.FormRequest{}, fmt.Errorf("fapitest: malformed parameter value: %w", err)
		}
		params = append(params, server.FormParameter{Name: decodedName, Value: decodedValue})
	}
	return server.FormRequest{Parameters: params}, nil
}
