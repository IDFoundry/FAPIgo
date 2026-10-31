package federation

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// FuzzFederationRequestsFromHTTP checks TrustMarkRequestFromHTTP
// (§8.6.1) and ResolveRequestFromHTTP (§8.3.1), which read a request
// anyone can send to a federation endpoint, on a fuzzed method, raw
// query and form body. Beyond never panicking:
//
//   - a refusal is always an ErrorInvalidRequest *Error with HTTP 400;
//   - only the query is read, never the body, whatever the method;
//   - what each accepts is the query's first "sub", a valid Entity
//     Identifier, with the other parameters exactly as the query
//     carries them: a non-empty trust_mark_type, or at least one
//     trust_anchor and every entity_type, in order;
//   - each refuses exactly when a parameter it requires is missing or
//     "sub" isn't a valid Entity Identifier.
func FuzzFederationRequestsFromHTTP(f *testing.F) {
	f.Add(uint8(0), "trust_mark_type=https%3A%2F%2Ftm.example%2Fa&sub=https%3A%2F%2Frp.example", "")
	f.Add(uint8(0), "sub=https://rp.example&trust_anchor=https://ta.example&trust_anchor=&entity_type=openid_provider", "")
	f.Add(uint8(1), "", "sub=https://rp.example&trust_anchor=https://ta.example&trust_mark_type=t")
	f.Add(uint8(0), "sub=https://rp.example&sub=http://evil.example&trust_anchor=x", "")
	f.Add(uint8(0), "sub=https%3A%2F%2Frp.example%3Fx%3D1&trust_anchor=x&trust_mark_type=t", "")
	f.Add(uint8(0), "sub=https://rp.example;trust_anchor=x&trust_mark_type=%zz", "")
	f.Fuzz(func(t *testing.T, method uint8, rawQuery, form string) {
		r := &http.Request{
			Method: []string{http.MethodGet, http.MethodPost, http.MethodHead}[method%3],
			URL:    &url.URL{Scheme: "https", Host: "fed.example", Path: "/endpoint", RawQuery: rawQuery},
			Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
			Body:   http.NoBody,
		}
		if form != "" {
			r.Body = stringBody{strings.NewReader(form)}
		}
		query := r.URL.Query()
		checkTrustMarkRequest(t, r, query)
		checkResolveRequest(t, r, query)
	})
}

type stringBody struct{ *strings.Reader }

func (stringBody) Close() error { return nil }

// subjectRefusal reports whether a request with query must be refused
// for its "sub": absent, empty or not an Entity Identifier.
func subjectRefusal(query url.Values) bool {
	sub := query.Get("sub")
	return sub == "" || ValidEntityID(sub) != nil
}

func checkTrustMarkRequest(t *testing.T, r *http.Request, query url.Values) {
	t.Helper()
	trustMarkType, subject, err := TrustMarkRequestFromHTTP(r)
	wantRefusal := query.Get("trust_mark_type") == "" || subjectRefusal(query)
	if (err != nil) != wantRefusal {
		t.Fatalf("TrustMarkRequestFromHTTP(%q) = %q, %q, %v; want refusal %v", r.URL.RawQuery, trustMarkType, subject, err, wantRefusal)
	}
	if err != nil {
		checkRequestRefusal(t, "TrustMarkRequestFromHTTP", err)
		return
	}
	if trustMarkType != query.Get("trust_mark_type") || subject != query.Get("sub") || ValidEntityID(subject) != nil {
		t.Fatalf("TrustMarkRequestFromHTTP(%q) = %q, %q; not the query's own values", r.URL.RawQuery, trustMarkType, subject)
	}
}

func checkResolveRequest(t *testing.T, r *http.Request, query url.Values) {
	t.Helper()
	subject, anchors, entityTypes, err := ResolveRequestFromHTTP(r)
	wantRefusal := subjectRefusal(query) || len(query["trust_anchor"]) == 0
	if (err != nil) != wantRefusal {
		t.Fatalf("ResolveRequestFromHTTP(%q) = %q, %q, %q, %v; want refusal %v", r.URL.RawQuery, subject, anchors, entityTypes, err, wantRefusal)
	}
	if err != nil {
		checkRequestRefusal(t, "ResolveRequestFromHTTP", err)
		return
	}
	if subject != query.Get("sub") || ValidEntityID(subject) != nil || len(anchors) == 0 ||
		!slices.Equal(anchors, query["trust_anchor"]) || !slices.Equal(entityTypes, query["entity_type"]) {
		t.Fatalf("ResolveRequestFromHTTP(%q) = %q, %q, %q; not the query's own values", r.URL.RawQuery, subject, anchors, entityTypes)
	}
}

// checkRequestRefusal checks err is an invalid_request *Error for HTTP
// 400, ready for WriteJSON.
func checkRequestRefusal(t *testing.T, name string, err error) {
	t.Helper()
	var fe *Error
	if !errors.As(err, &fe) || fe.Code() != ErrorInvalidRequest || fe.HTTPStatus() != http.StatusBadRequest {
		t.Fatalf("%s refused with %v, want an invalid_request *Error for HTTP 400", name, err)
	}
}
