package dpop

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// signClaims signs a proof with htm and htu written verbatim, as another
// client library might, at now.
func signClaims(t *testing.T, htm, htu string, now time.Time) string {
	t.Helper()
	key := generateKey(t)
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"jti": "j-" + htm + htu, "htm": htm, "htu": htu, "iat": now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType, JWK: &jwk}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func verifyAt(t *testing.T, proof, method string, target *url.URL, alternates []*url.URL, now time.Time) error {
	t.Helper()
	_, err := Verify(context.Background(), VerifyRequest{
		Proof: proof, Method: method, URL: target, AlternateURLs: alternates,
		Now: now, MaxProofAge: time.Minute,
	})
	return err
}

// TestVerifyRefusesRelativeOrNonHTTPHTU: an htu that is a relative
// reference, or names another scheme than http(s), binds the proof to no
// origin, so it never verifies, not even at a target whose path it
// names.
func TestVerifyRefusesRelativeOrNonHTTPHTU(t *testing.T) {
	now := time.Now()
	target := mustURL(t, "https://rs.example/accounts")
	for _, htu := range []string{"/accounts", "//rs.example/accounts", "ftp://rs.example/accounts", "FTP://RS.example/accounts", "urn:x:accounts", "https:///accounts"} {
		if err := verifyAt(t, signClaims(t, "GET", htu, now), "GET", target, nil, now); !errors.Is(err, ErrURIMismatch) {
			t.Errorf("htu %q at %s: err = %v, want ErrURIMismatch", htu, target, err)
		}
	}
	if err := verifyAt(t, signClaims(t, "GET", "HTTPS://RS.example/accounts", now), "GET", target, nil, now); err != nil {
		t.Errorf("htu differing only in ASCII case: err = %v, want nil", err)
	}
}

// TestVerifyRefusesRelativeOrNonHTTPTarget: a target that isn't an
// absolute http(s) URL with a host is the caller's error, refused before
// any htu is compared with it — including an adapter passing a server
// request's own r.URL, which is just its path.
func TestVerifyRefusesRelativeOrNonHTTPTarget(t *testing.T) {
	now := time.Now()
	for _, target := range []string{"/accounts", "ftp://rs.example/accounts", "rs.example/accounts", "https:///accounts", "mailto:a@rs.example"} {
		u := mustURL(t, target)
		if err := verifyAt(t, signClaims(t, "GET", target, now), "GET", u, nil, now); err == nil || errors.Is(err, ErrURIMismatch) {
			t.Errorf("target %q: err = %v, want a refused target", target, err)
		}
		good := mustURL(t, "https://rs.example/accounts")
		if err := verifyAt(t, signClaims(t, "GET", good.String(), now), "GET", good, []*url.URL{u}, now); err == nil || errors.Is(err, ErrURIMismatch) {
			t.Errorf("alternate target %q: err = %v, want a refused target", target, err)
		}
	}
}

// TestVerifyComparesMethodExactly: methods are case-sensitive (RFC 9110
// §9.1), so a proof for GET doesn't verify on a request made as "get",
// nor one for "get" on a GET.
func TestVerifyComparesMethodExactly(t *testing.T) {
	now := time.Now()
	target := mustURL(t, "https://rs.example/x")
	cases := []struct {
		htm, method string
		ok          bool
	}{
		{"GET", "GET", true},
		{"GET", "get", false},
		{"GET", "gEt", false},
		{"get", "GET", false},
		{"get", "get", true},
	}
	for _, c := range cases {
		err := verifyAt(t, signClaims(t, c.htm, target.String(), now), c.method, target, nil, now)
		if c.ok != (err == nil) || (!c.ok && !errors.Is(err, ErrMethodMismatch)) {
			t.Errorf("htm %q, method %q: err = %v, want ok=%v", c.htm, c.method, err, c.ok)
		}
	}
}

// TestCreateProofKeepsMethodAsGiven: CreateProof writes htm exactly as
// the request is sent, so a proof for a request sent as "get" verifies
// there.
func TestCreateProofKeepsMethodAsGiven(t *testing.T) {
	now := time.Now()
	target := mustURL(t, "https://rs.example/x")
	proof, err := CreateProof(ProofRequest{Signer: generateKey(t), Algorithm: fapi.ES256, Method: "get", URL: target, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAt(t, proof, "get", target, nil, now); err != nil {
		t.Errorf("verify at get: %v", err)
	}
	if err := verifyAt(t, proof, "GET", target, nil, now); !errors.Is(err, ErrMethodMismatch) {
		t.Errorf("verify at GET: err = %v, want ErrMethodMismatch", err)
	}
}

// TestVerifyAcceptsAnAlternateTarget: an htu naming any one of the
// targets verifies; one naming none of them doesn't.
func TestVerifyAcceptsAnAlternateTarget(t *testing.T) {
	now := time.Now()
	primary := mustURL(t, "https://rs.example/accounts")
	alternates := []*url.URL{mustURL(t, "https://mtls.rs.example/accounts")}
	if err := verifyAt(t, signClaims(t, "GET", "https://mtls.rs.example/accounts", now), "GET", primary, alternates, now); err != nil {
		t.Errorf("htu naming the alternate: %v", err)
	}
	if err := verifyAt(t, signClaims(t, "GET", "https://other.example/accounts", now), "GET", primary, alternates, now); !errors.Is(err, ErrURIMismatch) {
		t.Errorf("htu naming neither: err = %v, want ErrURIMismatch", err)
	}
}
