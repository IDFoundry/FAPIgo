package server_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

func newFormPOST(t *testing.T, contentType, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func TestFormRequestFromHTTPPreservesOrderAndDuplicates(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "grant_type=client_credentials&scope=a+b&scope=c")
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("FormRequestFromHTTP: %v", err)
	}
	want := []server.FormParameter{
		{Name: "grant_type", Value: "client_credentials"},
		{Name: "scope", Value: "a b"},
		{Name: "scope", Value: "c"},
	}
	if len(form.Parameters) != len(want) {
		t.Fatalf("Parameters = %v, want %v", form.Parameters, want)
	}
	for i, p := range form.Parameters {
		if p != want[i] {
			t.Errorf("Parameters[%d] = %+v, want %+v", i, p, want[i])
		}
	}
}

func TestFormRequestFromHTTPAcceptsContentTypeWithCharset(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded; charset=UTF-8", "grant_type=refresh_token")
	if _, err := server.FormRequestFromHTTP(r); err != nil {
		t.Fatalf("FormRequestFromHTTP: %v", err)
	}
}

func TestFormRequestFromHTTPRejectsWrongContentType(t *testing.T) {
	r := newFormPOST(t, "application/json", `{"grant_type":"refresh_token"}`)
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(wrong content type) = nil error, want error")
	}
}

func TestFormRequestFromHTTPRejectsMalformedParameterName(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "%zz=value")
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(malformed name) = nil error, want error")
	}
}

func TestFormRequestFromHTTPRejectsMalformedParameterValue(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "grant_type=%zz")
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(malformed value) = nil error, want error")
	}
}

func TestFormRequestFromHTTPRejectsOversizedBody(t *testing.T) {
	huge := "grant_type=" + strings.Repeat("a", 1<<20+1)
	r := newFormPOST(t, "application/x-www-form-urlencoded", huge)
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(oversized body) = nil error, want error")
	}
}

func TestFormRequestFromHTTPAcceptsEmptyBody(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "")
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("FormRequestFromHTTP: %v", err)
	}
	if len(form.Parameters) != 0 {
		t.Fatalf("Parameters = %v, want empty", form.Parameters)
	}
}

// TestFormRequestGetReturnsFirstMatch covers Get's own first-match
// semantics, distinct from this package's internal duplicate-rejecting
// parameter handling — see Get's own doc comment for why that
// difference is deliberate.
func TestFormRequestGetReturnsFirstMatch(t *testing.T) {
	form := server.FormRequest{Parameters: []server.FormParameter{
		{Name: "grant_type", Value: "authorization_code"},
		{Name: "grant_type", Value: "refresh_token"},
		{Name: "code", Value: "abc123"},
	}}

	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Fatalf("Get(grant_type) = %q, want %q (first occurrence)", got, "authorization_code")
	}
	if got := form.Get("code"); got != "abc123" {
		t.Fatalf("Get(code) = %q, want %q", got, "abc123")
	}
}

// TestFormRequestGetAbsentReturnsEmpty covers Get's other branch: a
// name that never appears returns "", not an error.
func TestFormRequestGetAbsentReturnsEmpty(t *testing.T) {
	form := server.FormRequest{Parameters: []server.FormParameter{
		{Name: "code", Value: "abc123"},
	}}

	if got := form.Get("grant_type"); got != "" {
		t.Fatalf("Get(grant_type) = %q, want \"\" for an absent parameter", got)
	}
}

// numberedForm is n parameters, p0=v0 to p<n-1>=v<n-1>, joined by sep.
func numberedForm(n int, sep string) string {
	pairs := make([]string, n)
	for i := range pairs {
		pairs[i] = fmt.Sprintf("p%d=v%d", i, i)
	}
	return strings.Join(pairs, sep)
}

// bytesAllocated is testing.AllocsPerRun in bytes: the heap bytes one
// call to f allocates, averaged over runs calls after a first that
// warms up. Like AllocsPerRun, it measures at GOMAXPROCS 1, so other
// goroutines add little to it.
func bytesAllocated(runs int, f func()) uint64 {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	f()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(runs)
}

// TestFormRequestFromHTTPBoundsParameterCount: a body may carry 100
// parameters, counted as the server's methods count a FormRequest's,
// so the empty pairs around and between them are none; the 101st is
// refused before it is decoded, so a malformed one is refused for the
// count too.
func TestFormRequestFromHTTPBoundsParameterCount(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	atLimit, err := server.FormRequestFromHTTP(newFormPOST(t, form, "&&"+numberedForm(100, "&&&")+"&"))
	if err != nil {
		t.Fatalf("FormRequestFromHTTP(100 parameters): %v", err)
	}
	if n := len(atLimit.Parameters); n != 100 || atLimit.Parameters[0] != (server.FormParameter{Name: "p0", Value: "v0"}) || atLimit.Parameters[99] != (server.FormParameter{Name: "p99", Value: "v99"}) {
		t.Fatalf("Parameters = %d of them, want p0=v0 to p99=v99", n)
	}

	for name, body := range map[string]string{
		"101 parameters":    numberedForm(101, "&"),
		"a malformed 101st": numberedForm(100, "&") + "&%zz=v",
		// 1 MiB, within the size limit: 524,288 one-byte parameters.
		"many tiny parameters": strings.Repeat("a&", 1<<19),
	} {
		_, err := server.FormRequestFromHTTP(newFormPOST(t, form, body))
		if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
			t.Errorf("%s: error code %q, want %q", name, code, server.ErrorInvalidRequest)
		}
		if got := serverErrorDescription(t, err); got != "the request body has too many parameters" {
			t.Errorf("%s: description %q, want the parameter count's", name, got)
		}
	}

	// Separators alone are no parameters, however many there are.
	separators, err := server.FormRequestFromHTTP(newFormPOST(t, form, strings.Repeat("&", 1<<20)))
	if err != nil || len(separators.Parameters) != 0 {
		t.Fatalf("FormRequestFromHTTP(1 MiB of separators) = %d parameters, %v; want none", len(separators.Parameters), err)
	}
}

// TestFormRequestFromHTTPAllocationIsBounded: taking a 1 MiB body costs
// about what reading it does, however many pairs it splits into —
// 524,288 one-byte parameters, or separators alone — rather than growing
// with each pair.
func TestFormRequestFromHTTPAllocationIsBounded(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	for name, body := range map[string]string{
		"many tiny parameters": strings.Repeat("a&", 1<<19),
		"separators only":      strings.Repeat("&", 1<<20),
	} {
		allocated := bytesAllocated(4, func() {
			_, _ = server.FormRequestFromHTTP(newFormPOST(t, form, body))
		})
		if allocated > 8<<20 {
			t.Errorf("%s: FormRequestFromHTTP allocated %d bytes for a 1 MiB body, want at most 8 MiB", name, allocated)
		}
	}
}

// TestFormRequestFromHTTPCopiesAValueOnce: a value is copied out of the
// body once, whether or not it has to be unescaped (unescaping it
// already builds a string of its own), so a body that is one long value
// costs about that value's length more to take than a body as long with
// nothing in it to decode: what reading the body costs is the same.
func TestFormRequestFromHTTPCopiesAValueOnce(t *testing.T) {
	const form, length = "application/x-www-form-urlencoded", 1 << 19
	take := func(value string) uint64 {
		body := "v=" + value
		return bytesAllocated(4, func() {
			_, _ = server.FormRequestFromHTTP(newFormPOST(t, form, body))
		})
	}
	reading := take(strings.Repeat("&", length))
	for name, value := range map[string]string{
		"unescaped": strings.Repeat("a", length),
		"escaped":   strings.Repeat("+", length),
	} {
		if taking := take(value); taking > reading+length+length/2 {
			t.Errorf("%s: taking a %d-byte value allocated %d bytes, %d for a body with nothing to decode: want the value copied once", name, length, taking, reading)
		}
	}
}
