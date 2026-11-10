package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// nonceOnlyOnChallengeServer is a resource server that requires a DPoP
// nonce on every request and, as RFC 9449 §8.2 allows, sends DPoP-Nonce
// only on its use_dpop_nonce challenge, never on a success: the nonce
// hasn't changed, so there's nothing new to supply.
type nonceOnlyOnChallengeServer struct {
	t           *testing.T
	nonce       string
	mu          sync.Mutex
	calls       int
	proofNonces []string
}

func (s *nonceOnlyOnChallengeServer) handler(ok func(http.ResponseWriter)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := dpopProofClaims(s.t, r.Header.Get("DPoP"))["nonce"].(string)
		s.mu.Lock()
		s.calls++
		s.proofNonces = append(s.proofNonces, got)
		s.mu.Unlock()
		if got != s.nonce {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="nonce required"`)
			w.Header().Set("DPoP-Nonce", s.nonce)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ok(w)
	})
}

// check asserts the two calls took exactly one challenge: the first
// call's challenge and retry, then a second call carrying the
// challenge's nonce from the start.
func (s *nonceOnlyOnChallengeServer) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls != 3 {
		t.Fatalf("server received %d requests for two calls, want 3 (challenge, retry, then no challenge); proof nonces %q", s.calls, s.proofNonces)
	}
	if s.proofNonces[2] != s.nonce {
		t.Errorf("second call's proof nonce = %q, want the challenge's %q", s.proofNonces[2], s.nonce)
	}
}

// TestProtectedResourceDoCachesChallengeNonce: the nonce a resource
// server's use_dpop_nonce challenge supplies is the one to use on every
// later request (RFC 9449 §8.2, via §9), even when the retry's response
// repeats no DPoP-Nonce header.
func TestProtectedResourceDoCachesChallengeNonce(t *testing.T) {
	rs := &nonceOnlyOnChallengeServer{t: t, nonce: "rs-nonce-1"}
	ts := httptest.NewServer(rs.handler(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, nil)
	for i := range 2 {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req)
		if err != nil {
			t.Fatalf("Do #%d: %v", i+1, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Do #%d: status = %d, want 200", i+1, res.StatusCode)
		}
	}
	rs.check(t)
}

// TestFetchUserInfoCachesChallengeNonce is the same for UserInfo, which
// the same nonce rules apply to (it's a protected resource).
func TestFetchUserInfoCachesChallengeNonce(t *testing.T) {
	rs := &nonceOnlyOnChallengeServer{t: t, nonce: "userinfo-nonce-1"}
	ts := httptest.NewServer(rs.handler(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": userInfoTestSubject})
	}))
	defer ts.Close()

	c := newUserInfoTestClient(t, ts, nil, nil, nil)
	for i := range 2 {
		if _, err := c.FetchUserInfo(context.Background(), userInfoTestTokens()); err != nil {
			t.Fatalf("FetchUserInfo #%d: %v", i+1, err)
		}
	}
	rs.check(t)
}
