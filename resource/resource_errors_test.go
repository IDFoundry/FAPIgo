package resource_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
)

// TestInsufficientScopeChallengeFollowsTokenScheme covers RFC 9449 §7.1:
// a verified token refused for insufficient scope is challenged in the
// scheme it was presented with — DPoP for a DPoP-bound token, Bearer
// for an mTLS-bound one (and for an AuthorizationContext Verify didn't
// produce).
func TestInsufficientScopeChallengeFollowsTokenScheme(t *testing.T) {
	dpopFixture := newFixture(t)
	dpopAuthz, err := dpopFixture.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: dpopFixture.target,
		Authorization: "DPoP " + dpopFixture.accessToken,
		DPoPProofs:    []string{dpopFixture.dpopProof},
	})
	if err != nil {
		t.Fatalf("Verify(DPoP): %v", err)
	}
	mtlsFixture := newMTLSFixture(t)
	mtlsAuthz, err := mtlsFixture.verifier.Verify(context.Background(), resource.VerifyRequest{
		Method: "GET", URL: mtlsFixture.target,
		Authorization:   "Bearer " + mtlsFixture.accessToken,
		PeerCertificate: mtlsFixture.cert,
	})
	if err != nil {
		t.Fatalf("Verify(mTLS): %v", err)
	}

	for _, tc := range []struct {
		name  string
		authz resource.AuthorizationContext
		want  string
	}{
		{"DPoP-bound", dpopAuthz, `DPoP error="insufficient_scope", algs="ES256 PS256 EdDSA"`},
		{"mTLS-bound", mtlsAuthz, `Bearer error="insufficient_scope"`},
		{"not from Verify", resource.AuthorizationContext{}, `Bearer error="insufficient_scope"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := resource.NewInsufficientScopeError(tc.authz, "payments need the payments scope")
			if e.Code() != resource.ErrorInsufficientScope || e.HTTPStatus() != 403 {
				t.Fatalf("NewInsufficientScopeError = %s/%d, want insufficient_scope/403", e.Code(), e.HTTPStatus())
			}
			rec := httptest.NewRecorder()
			e.WriteJSON(rec)
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.want)
			}
			if rec.Code != 403 {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
}

// TestNewErrorNormalizesInvalidInput: a code outside RFC 6750 §3's
// character set, or a status that isn't 4xx/5xx, can neither inject
// into the challenge nor panic when written; it becomes a 500
// server_error. A description outside the character set is dropped.
func TestNewErrorNormalizesInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name                string
		code                resource.ErrorCode
		status              int
		description         string
		wantCode            resource.ErrorCode
		wantStatus          int
		wantDescription     string
		wantWWWAuthenticate string
	}{
		{"valid", resource.ErrorInvalidRequest, 400, "bad header", resource.ErrorInvalidRequest, 400, "bad header", `Bearer error="invalid_request"`},
		{"code injecting a challenge parameter", `invalid_token", scope="admin`, 401, "x", resource.ErrorServerError, 500, "x", `Bearer error="server_error"`},
		{"code with a newline", "invalid_token\r\nX-Injected: 1", 401, "", resource.ErrorServerError, 500, "", `Bearer error="server_error"`},
		{"status zero", resource.ErrorInvalidRequest, 0, "", resource.ErrorServerError, 500, "", `Bearer error="server_error"`},
		{"status out of range", resource.ErrorInvalidRequest, 1000, "", resource.ErrorServerError, 500, "", `Bearer error="server_error"`},
		{"success status", resource.ErrorInvalidRequest, 200, "", resource.ErrorServerError, 500, "", `Bearer error="server_error"`},
		{"description outside the character set", resource.ErrorInvalidRequest, 400, "costs €5", resource.ErrorInvalidRequest, 400, "", `Bearer error="invalid_request"`},
		{"no credentials", "", 401, "", "", 401, "", `Bearer, DPoP algs="ES256 PS256 EdDSA"`},
		{"no code with another status", "", 403, "", resource.ErrorServerError, 500, "", `Bearer error="server_error"`},
		{"no code with a 500", "", 500, "", resource.ErrorServerError, 500, "", `Bearer error="server_error"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := resource.NewError(tc.code, tc.status, tc.description)
			if e.Code() != tc.wantCode || e.HTTPStatus() != tc.wantStatus || e.PublicDescription() != tc.wantDescription {
				t.Fatalf("NewError = %q/%d/%q, want %q/%d/%q", e.Code(), e.HTTPStatus(), e.PublicDescription(), tc.wantCode, tc.wantStatus, tc.wantDescription)
			}
			rec := httptest.NewRecorder()
			e.WriteJSON(rec)
			if rec.Code != tc.wantStatus {
				t.Errorf("written status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.wantWWWAuthenticate {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.wantWWWAuthenticate)
			}
		})
	}
}

// TestZeroErrorWriteJSONDoesNotPanic: an *Error that never went
// through a constructor writes a 500 rather than panicking in
// WriteHeader.
func TestZeroErrorWriteJSONDoesNotPanic(t *testing.T) {
	rec := httptest.NewRecorder()
	new(resource.Error).WriteJSON(rec)
	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

type failingAccessTokenStore struct{ err error }

func (failingAccessTokenStore) CreateAccessToken(context.Context, storage.NewAccessToken) error {
	return nil
}

func (s failingAccessTokenStore) LookupAccessToken(context.Context, storage.AccessTokenLookup) (storage.LookedUpAccessToken, error) {
	return storage.LookedUpAccessToken{}, s.err
}

type bareErrorResolver struct{ err error }

func (r bareErrorResolver) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	return resource.ResolvedAccessToken{}, r.err
}

// TestAccessTokenLookupFailureClassification: a cancelled or timed-out
// lookup is a 500 server_error, not a claim that the token is invalid;
// any other lookup error still means an unknown token, 401
// invalid_token. Both for OpaqueAccessTokens and for a third-party
// resolver returning a bare error through Verify.
func TestAccessTokenLookupFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantCode   resource.ErrorCode
		wantStatus int
	}{
		{"unknown token", errors.New("not found"), resource.ErrorInvalidToken, 401},
		{"deadline exceeded", fmt.Errorf("db: %w", context.DeadlineExceeded), resource.ErrorServerError, 500},
		{"cancelled", fmt.Errorf("db: %w", context.Canceled), resource.ErrorServerError, 500},
		{"store unavailable", fmt.Errorf("db: %w", storage.ErrStoreUnavailable), resource.ErrorServerError, 500},
	} {
		t.Run("opaque "+tc.name, func(t *testing.T) {
			_, err := resource.OpaqueAccessTokens{Store: failingAccessTokenStore{err: tc.err}}.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: "tok"})
			assertResourceError(t, err, tc.wantCode, tc.wantStatus, tc.err)
		})
		t.Run("bare resolver "+tc.name, func(t *testing.T) {
			f := newOpaqueFixture(t, time.Minute)
			v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
				AccessTokens: bareErrorResolver{err: tc.err},
				Replay:       &fakeReplayStore{},
				Revocation:   &fakeRevocationChecker{},
				Clock:        fixedClock{now: f.now},
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			_, err = v.Verify(context.Background(), resource.VerifyRequest{
				Method: "GET", URL: f.target,
				Authorization: "DPoP " + f.rawToken,
				DPoPProofs:    []string{f.proof(t, f.dpopKey)},
			})
			assertResourceError(t, err, tc.wantCode, tc.wantStatus, tc.err)
		})
	}
}

// TestVerifyPropagatesAWrappedResolverError: a resolver's own *Error
// carries its exposure even when the resolver wraps it, rather than
// falling back to invalid_token.
func TestVerifyPropagatesAWrappedResolverError(t *testing.T) {
	own := resource.NewError(resource.ErrorServerError, 503, "issuer keys unreachable")
	for name, err := range map[string]error{
		"as is":   own,
		"wrapped": fmt.Errorf("resolve: %w", own),
	} {
		t.Run(name, func(t *testing.T) {
			f := newOpaqueFixture(t, time.Minute)
			v, verr := resource.NewVerifier(validConfig(t), resource.Dependencies{
				AccessTokens: bareErrorResolver{err: err},
				Replay:       &fakeReplayStore{},
				Revocation:   &fakeRevocationChecker{},
				Clock:        fixedClock{now: f.now},
			})
			if verr != nil {
				t.Fatalf("NewVerifier: %v", verr)
			}
			_, got := v.Verify(context.Background(), resource.VerifyRequest{
				Method: "GET", URL: f.target,
				Authorization: "DPoP " + f.rawToken,
				DPoPProofs:    []string{f.proof(t, f.dpopKey)},
			})
			var rerr *resource.Error
			if !errors.As(got, &rerr) || rerr.Code() != resource.ErrorServerError || rerr.HTTPStatus() != 503 {
				t.Fatalf("Verify = %v, want the resolver's own server_error 503", got)
			}
		})
	}
}

func assertResourceError(t *testing.T, err error, wantCode resource.ErrorCode, wantStatus int, wantCause error) {
	t.Helper()
	var rerr *resource.Error
	if !errors.As(err, &rerr) {
		t.Fatalf("err = %v, want *resource.Error", err)
	}
	if rerr.Code() != wantCode || rerr.HTTPStatus() != wantStatus {
		t.Errorf("err = %s/%d, want %s/%d", rerr.Code(), rerr.HTTPStatus(), wantCode, wantStatus)
	}
	if !errors.Is(err, wantCause) {
		t.Errorf("err doesn't wrap the store's error %v", wantCause)
	}
}

// TestDPoPStoreUnavailable: a replay or nonce store that couldn't
// answer (wrapping storage.ErrStoreUnavailable, or a cancelled or
// timed-out context) is a 500 server_error, not a refused DPoP proof
// or a fresh nonce challenge; any other error keeps today's answer.
func TestDPoPStoreUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantCode   resource.ErrorCode
		wantStatus int
	}{
		{"store unavailable", fmt.Errorf("redis: %w", storage.ErrStoreUnavailable), resource.ErrorServerError, 500},
		{"deadline exceeded", fmt.Errorf("redis: %w", context.DeadlineExceeded), resource.ErrorServerError, 500},
		{"cancelled", fmt.Errorf("redis: %w", context.Canceled), resource.ErrorServerError, 500},
	} {
		t.Run("replay "+tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.replay.err = tc.err
			_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
				Method: "GET", URL: f.target,
				Authorization: "DPoP " + f.accessToken,
				DPoPProofs:    []string{f.dpopProof},
			})
			assertResourceError(t, err, tc.wantCode, tc.wantStatus, tc.err)
		})
		t.Run("nonce "+tc.name, func(t *testing.T) {
			f := newNonceFixture(t, "presented-nonce", failingNonceStore{err: tc.err})
			_, err := f.verify(t)
			assertResourceError(t, err, tc.wantCode, tc.wantStatus, tc.err)
		})
	}

	t.Run("replay already used", func(t *testing.T) {
		f := newFixture(t)
		f.replay.err = errors.New("already used")
		_, err := f.verifier.Verify(context.Background(), resource.VerifyRequest{
			Method: "GET", URL: f.target,
			Authorization: "DPoP " + f.accessToken,
			DPoPProofs:    []string{f.dpopProof},
		})
		assertResourceError(t, err, resource.ErrorInvalidDPoPProof, 401, f.replay.err)
	})
	t.Run("nonce unknown", func(t *testing.T) {
		f := newNonceFixture(t, "presented-nonce", failingNonceStore{err: errors.New("unknown nonce")})
		_, err := f.verify(t)
		var rerr *resource.Error
		if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorUseDPoPNonce || rerr.HTTPStatus() != 401 {
			t.Fatalf("err = %v, want a 401 use_dpop_nonce challenge", err)
		}
	})
}

// failingNonceStore issues nonces but fails every Consume with err.
type failingNonceStore struct{ err error }

func (failingNonceStore) Issue(context.Context, storage.NonceIssuance) error { return nil }

func (s failingNonceStore) Consume(context.Context, storage.NonceConsumption) (storage.NonceRecord, error) {
	return storage.NonceRecord{}, s.err
}
