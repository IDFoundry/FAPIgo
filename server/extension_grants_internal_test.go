package server

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

func TestValidateAdditionalGrantTypes(t *testing.T) {
	const preAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	if err := validateAdditionalGrantTypes([]string{preAuthorizedCode, "urn:example:other"}); err != nil {
		t.Errorf("validateAdditionalGrantTypes(valid) = %v", err)
	}
	for name, grantTypes := range map[string][]string{
		"served by the package": {"authorization_code"},
		"CIBA":                  {CIBAGrantType},
		"password":              {"password"},
		"implicit":              {"implicit"},
		"empty":                 {""},
		"with a space":          {"a b"},
		"with a control":        {"a\x7f"},
		"duplicate":             {preAuthorizedCode, preAuthorizedCode},
	} {
		if err := validateAdditionalGrantTypes(grantTypes); err == nil {
			t.Errorf("validateAdditionalGrantTypes(%s) = nil error, want refusal", name)
		}
	}
}

// failingNonceStore can't issue a nonce.
type failingNonceStore struct{}

func (failingNonceStore) Issue(context.Context, storage.NonceIssuance) error {
	return errors.New("nonce store unavailable")
}

func (failingNonceStore) Consume(context.Context, storage.NonceConsumption) (storage.NonceRecord, error) {
	return storage.NonceRecord{}, errors.New("nonce store unavailable")
}

// TestNextDPoPNonceFailsWhenItCantIssue covers a nonce store that can't
// issue: a DPoP-bound client's token response fails with server_error
// rather than going out without the nonce it needs next.
func TestNextDPoPNonceFailsWhenItCantIssue(t *testing.T) {
	s := &Server{deps: Dependencies{Nonces: failingNonceStore{}, Random: rand.Reader}}
	var dpopClient storage.RegisteredClient // the zero value is DPoP-bound
	if _, err := s.nextDPoPNonce(context.Background(), dpopClient, time.Now()); err == nil || err.Code() != ErrorServerError {
		t.Errorf("nextDPoPNonce = %v, want server_error", err)
	}
	var result TokenResult
	if err := s.addNextDPoPNonce(context.Background(), dpopClient, time.Now(), &result); err == nil || err.Code() != ErrorServerError {
		t.Errorf("addNextDPoPNonce = %v, want server_error", err)
	}
}
