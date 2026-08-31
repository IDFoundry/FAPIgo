package server

import (
	"fmt"
	"io"
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
func FormRequestFromHTTP(r *http.Request) (FormRequest, error) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return FormRequest{}, fmt.Errorf("server: unexpected content type %q", ct)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFormRequestBytes+1))
	if err != nil {
		return FormRequest{}, fmt.Errorf("server: read body: %w", err)
	}
	if len(body) > maxFormRequestBytes {
		return FormRequest{}, fmt.Errorf("server: body exceeds %d bytes", maxFormRequestBytes)
	}

	var params []FormParameter
	for _, pair := range strings.Split(string(body), "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			return FormRequest{}, fmt.Errorf("server: malformed parameter name: %w", err)
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return FormRequest{}, fmt.Errorf("server: malformed parameter value: %w", err)
		}
		params = append(params, FormParameter{Name: decodedName, Value: decodedValue})
	}
	return FormRequest{Parameters: params}, nil
}
