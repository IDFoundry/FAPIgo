package clientattestation

import (
	"context"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

func TestCreatePoPRejectsInvalidInput(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	validReq := func() PoPCreateRequest {
		return PoPCreateRequest{
			Signer: key, Algorithm: fapi.ES256,
			ClientID: "https://client.example.com", Audience: "https://as.example.com",
			Now: now,
		}
	}
	cases := map[string]func(*PoPCreateRequest){
		"nil signer":        func(r *PoPCreateRequest) { r.Signer = nil },
		"invalid algorithm": func(r *PoPCreateRequest) { r.Algorithm = 0 },
		"empty client id":   func(r *PoPCreateRequest) { r.ClientID = "" },
		"empty audience":    func(r *PoPCreateRequest) { r.Audience = "" },
		"zero now":          func(r *PoPCreateRequest) { r.Now = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := validReq()
			mutate(&req)
			if _, err := CreatePoP(req); err == nil {
				t.Fatalf("CreatePoP(%s) = nil error, want error", name)
			}
		})
	}
}

// failingReader always returns an error, for exercising CreatePoP's
// jti-generation failure path — a local copy of
// clientassertion's own test helper of the same name and shape (a
// different package, so it can't be shared without a new exported
// test-support package neither side has a reason to add).
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("simulated read failure") }

func TestCreatePoPPropagatesRandomSourceError(t *testing.T) {
	key := generateKey(t)
	_, err := CreatePoP(PoPCreateRequest{
		Signer: key, Algorithm: fapi.ES256,
		ClientID: "https://client.example.com", Audience: "https://as.example.com",
		Now: time.Now(), Random: failingReader{},
	})
	if err == nil {
		t.Fatalf("CreatePoP(failing random source) = nil error, want error")
	}
}

// TestCreatePoPRoundTripsWithVerify is the test that actually matters:
// it proves CreatePoP's own output is accepted byte-for-byte by
// ParsePoP/PoP.Verify — the same verification code
// server/client_auth_attestation.go already runs in production —
// rather than trusting that construction and verification agree on
// the wire format by symmetric assumption alone.
func TestCreatePoPRoundTripsWithVerify(t *testing.T) {
	instanceKey := generateKey(t)
	clientID := fapi.ClientID("https://client.example.com")
	audience := "https://as.example.com"
	now := time.Now()

	compact, err := CreatePoP(PoPCreateRequest{
		Signer: instanceKey, Algorithm: fapi.ES256,
		ClientID: clientID, Audience: audience, Now: now,
	})
	if err != nil {
		t.Fatalf("CreatePoP: %v", err)
	}

	parsed, err := ParsePoP(compact)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if parsed.ClaimedIssuer() != string(clientID) {
		t.Errorf("ClaimedIssuer() = %q, want %q", parsed.ClaimedIssuer(), clientID)
	}
	if parsed.Algorithm() != fapi.ES256 {
		t.Errorf("Algorithm() = %v, want %v", parsed.Algorithm(), fapi.ES256)
	}

	confirmationJWK := confirmationJWK(t, &instanceKey.PublicKey)
	verified, err := parsed.Verify(context.Background(), confirmationJWK, PoPVerifyPolicy{
		ExpectedIssuer: string(clientID), ExpectedAudience: audience,
		Now: now, MaxAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.ClientID != string(clientID) {
		t.Errorf("VerifiedPoP.ClientID = %q, want %q", verified.ClientID, clientID)
	}
	if !verified.IssuedAt.Equal(now.Truncate(time.Second)) {
		t.Errorf("VerifiedPoP.IssuedAt = %v, want %v", verified.IssuedAt, now.Truncate(time.Second))
	}
}

// TestCreatePoPRoundTrip_RejectsWrongInstanceKey confirms Verify still
// rejects a PoP signed by the wrong key even though CreatePoP itself
// has no way to check that its own Signer matches a given confirmation
// JWK — that correspondence is entirely the caller's own
// responsibility (see PoPCreateRequest.Signer's own doc comment), and
// this proves Verify is what actually enforces it.
func TestCreatePoPRoundTrip_RejectsWrongInstanceKey(t *testing.T) {
	instanceKey := generateKey(t)
	wrongKey := generateKey(t)
	clientID := fapi.ClientID("https://client.example.com")
	audience := "https://as.example.com"
	now := time.Now()

	compact, err := CreatePoP(PoPCreateRequest{
		Signer: wrongKey, Algorithm: fapi.ES256,
		ClientID: clientID, Audience: audience, Now: now,
	})
	if err != nil {
		t.Fatalf("CreatePoP: %v", err)
	}
	parsed, err := ParsePoP(compact)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}

	confirmationJWK := confirmationJWK(t, &instanceKey.PublicKey)
	if _, err := parsed.Verify(context.Background(), confirmationJWK, PoPVerifyPolicy{
		ExpectedIssuer: string(clientID), ExpectedAudience: audience,
		Now: now, MaxAge: time.Minute,
	}); err == nil {
		t.Fatal("Verify accepted a PoP signed by the wrong instance key")
	}
}
