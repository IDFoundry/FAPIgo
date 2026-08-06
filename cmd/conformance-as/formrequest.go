package main

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
// own r.ParseForm/r.PostForm would apply, so server (not this adapter)
// detects duplicate or malformed parameters. Ported from
// fapitest/form.go's formRequestFromHTTP.
func formRequestFromHTTP(r *http.Request) (server.FormRequest, error) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return server.FormRequest{}, fmt.Errorf("conformance-as: unexpected content type %q", ct)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFormBytes+1))
	if err != nil {
		return server.FormRequest{}, fmt.Errorf("conformance-as: read body: %w", err)
	}
	if len(body) > maxFormBytes {
		return server.FormRequest{}, fmt.Errorf("conformance-as: body exceeds %d bytes", maxFormBytes)
	}

	var params []server.FormParameter
	for _, pair := range strings.Split(string(body), "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			return server.FormRequest{}, fmt.Errorf("conformance-as: malformed parameter name: %w", err)
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return server.FormRequest{}, fmt.Errorf("conformance-as: malformed parameter value: %w", err)
		}
		params = append(params, server.FormParameter{Name: decodedName, Value: decodedValue})
	}
	return server.FormRequest{Parameters: params}, nil
}

// formValue returns the first value of name in form, or "" if absent.
func formValue(form server.FormRequest, name string) string {
	for _, p := range form.Parameters {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
