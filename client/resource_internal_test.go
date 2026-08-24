package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsResourceDPoPNonceChallengeRequiresBothSignals(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header http.Header
		want   bool
	}{
		{
			name:   "full challenge",
			status: http.StatusUnauthorized,
			header: http.Header{
				"Www-Authenticate": []string{`DPoP error="use_dpop_nonce"`},
				"Dpop-Nonce":       []string{"n"},
			},
			want: true,
		},
		{
			name:   "nonce header alone, no challenge",
			status: http.StatusUnauthorized,
			header: http.Header{"Dpop-Nonce": []string{"n"}},
			want:   false,
		},
		{
			name:   "challenge header alone, no nonce",
			status: http.StatusUnauthorized,
			header: http.Header{"Www-Authenticate": []string{`DPoP error="use_dpop_nonce"`}},
			want:   false,
		},
		{
			name:   "wrong status",
			status: http.StatusForbidden,
			header: http.Header{
				"Www-Authenticate": []string{`DPoP error="use_dpop_nonce"`},
				"Dpop-Nonce":       []string{"n"},
			},
			want: false,
		},
		{
			name:   "www-authenticate names a different scheme",
			status: http.StatusUnauthorized,
			header: http.Header{
				"Www-Authenticate": []string{`Bearer error="use_dpop_nonce"`},
				"Dpop-Nonce":       []string{"n"},
			},
			want: false,
		},
		{
			name:   "www-authenticate is DPoP but a different error",
			status: http.StatusUnauthorized,
			header: http.Header{
				"Www-Authenticate": []string{`DPoP error="invalid_token"`},
				"Dpop-Nonce":       []string{"n"},
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isResourceDPoPNonceChallenge(tc.status, tc.header); got != tc.want {
				t.Errorf("isResourceDPoPNonceChallenge(%d, %v) = %v, want %v", tc.status, tc.header, got, tc.want)
			}
		})
	}
}

func TestRebuildRequestBodyAllowsNilBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/resource", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	rebuilt, err := rebuildRequestBody(req)
	if err != nil {
		t.Fatalf("rebuildRequestBody: %v", err)
	}
	if rebuilt.Body != nil {
		t.Errorf("rebuilt.Body = %v, want nil", rebuilt.Body)
	}
}

func TestRebuildRequestBodyReplaysReplayableBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/resource", bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if req.GetBody == nil {
		t.Fatalf("test setup: req.GetBody is nil, want non-nil for *bytes.Reader")
	}
	// Drain the original body, as a first Do attempt would.
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatalf("drain original body: %v", err)
	}

	rebuilt, err := rebuildRequestBody(req)
	if err != nil {
		t.Fatalf("rebuildRequestBody: %v", err)
	}
	got, err := io.ReadAll(rebuilt.Body)
	if err != nil {
		t.Fatalf("read rebuilt body: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("rebuilt body = %q, want %q", got, "payload")
	}
}

// TestRebuildRequestBodyRejectsUnreplayableBody is the precise,
// non-network unit test for the property
// TestProtectedResourceDoRejectsUnreplayableBodyOnRetry exercises
// end-to-end: a request whose body has no GetBody must be rejected
// outright, not silently resent as whatever the (possibly already
// drained) reader happens to still hold.
func TestRebuildRequestBodyRejectsUnreplayableBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/resource", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader([]byte("payload")))
	req.GetBody = nil

	if _, err := rebuildRequestBody(req); err == nil {
		t.Fatalf("rebuildRequestBody(no GetBody) = nil error, want error")
	}
}

func TestBoundResponseBodyReturnsBodyWithinLimit(t *testing.T) {
	res := httptest.NewRecorder()
	res.Body = bytes.NewBufferString("hello")
	response := res.Result()

	bounded, err := boundResponseBody(response, 10)
	if err != nil {
		t.Fatalf("boundResponseBody: %v", err)
	}
	got, err := io.ReadAll(bounded.Body)
	if err != nil {
		t.Fatalf("read bounded body: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("body = %q, want %q", got, "hello")
	}
	if bounded.ContentLength != int64(len("hello")) {
		t.Errorf("ContentLength = %d, want %d", bounded.ContentLength, len("hello"))
	}
}

func TestBoundResponseBodyRejectsOversizedBody(t *testing.T) {
	res := httptest.NewRecorder()
	res.Body = bytes.NewBufferString("this body is too large for the limit")
	response := res.Result()

	if _, err := boundResponseBody(response, 4); err == nil {
		t.Fatalf("boundResponseBody(oversized) = nil error, want error")
	}
}

// alwaysErrorGetBody's GetBody always fails, so rebuildRequestBody must
// propagate that failure rather than treating it as "no body".
func TestRebuildRequestBodyPropagatesGetBodyError(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/resource", bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return nil, fmt.Errorf("boom")
	}

	if _, err := rebuildRequestBody(req); err == nil {
		t.Fatalf("rebuildRequestBody(failing GetBody) = nil error, want error")
	}
}
