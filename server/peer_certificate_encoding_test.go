package server_test

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// withoutEncoding is cert as a caller that built it field by field
// would pass it: every parsed field, but no DER encoding in Raw.
func withoutEncoding(cert *x509.Certificate) *x509.Certificate {
	built := *cert
	built.Raw = nil
	return &built
}

// assertMissingEncodingRefused checks err is the 500 server_error a
// PeerCertificate without its DER encoding gets, naming the cause.
func assertMissingEncodingRefused(t *testing.T, err error) {
	t.Helper()
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorServerError || serverErr.HTTPStatus() != 500 {
		t.Fatalf("err = %v, want a 500 server_error", err)
	}
	if !strings.Contains(err.Error(), "no DER encoding") {
		t.Errorf("Error() = %q, want the missing encoding named", err.Error())
	}
}

// TestCertificateClientAuthRefusesACertificateWithoutItsEncoding: a
// self_signed_tls_client_auth client presenting its own certificate,
// without the DER encoding its registered thumbprint is a digest of,
// isn't authenticated.
func TestCertificateClientAuthRefusesACertificateWithoutItsEncoding(t *testing.T) {
	h, cert := newHarnessWithClientAuthSelfSignedTLS(t)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP:            server.FormRequest{Parameters: certFormParameters(nil)},
		PeerCertificate: withoutEncoding(cert),
	})
	assertMissingEncodingRefused(t, err)
}

// TestCertificateBindingRefusesACertificateWithoutItsEncoding: an
// mTLS-bound client's token isn't bound to the digest of an empty
// encoding, which every such certificate shares.
func TestCertificateBindingRefusesACertificateWithoutItsEncoding(t *testing.T) {
	h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainMTLS, true)
	result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:            server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
		PeerCertificate: withoutEncoding(selfSignedTestClientCert(t)),
	})
	assertMissingEncodingRefused(t, err)
	if result.AccessToken.Reveal() != "" {
		t.Fatal("an access token was issued")
	}
}
