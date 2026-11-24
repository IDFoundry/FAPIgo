package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// otherHTTPClient is an HTTPClient that isn't an *http.Client.
type otherHTTPClient struct{}

func (otherHTTPClient) Do(*http.Request) (*http.Response, error) { return nil, nil }

// otherRoundTripper is a transport that isn't an *http.Transport.
type otherRoundTripper struct{}

func (otherRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

// TestCheckMTLSCertificateReadsOnlyWhatItCan: checkMTLSCertificate
// refuses only an HTTP client it can see presents no certificate. An
// HTTPClient that isn't an *http.Client, a transport that isn't an
// *http.Transport, and one with its own TLS dialer are left to their
// own configuration; a nil Transport is http.DefaultTransport, which
// presents none.
func TestCheckMTLSCertificateReadsOnlyWhatItCan(t *testing.T) {
	cfg := Config{SenderConstrain: storage.SenderConstrainMTLS}
	dialTLS := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}
	withCert := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{{}}}}
	for name, tc := range map[string]struct {
		client  any
		refused bool
	}{
		"not an *http.Client":    {otherHTTPClient{}, false},
		"nil Transport":          {&http.Client{}, true},
		"not an *http.Transport": {&http.Client{Transport: otherRoundTripper{}}, false},
		"its own TLS dialer":     {&http.Client{Transport: dialTLS}, false},
		"no TLSClientConfig":     {&http.Client{Transport: &http.Transport{}}, true},
		"a certificate":          {&http.Client{Transport: withCert}, false},
	} {
		httpClient := tc.client.(interface {
			Do(*http.Request) (*http.Response, error)
		})
		if err := checkMTLSCertificate(cfg, httpClient); (err != nil) != tc.refused {
			t.Errorf("%s: checkMTLSCertificate = %v, want refused %v", name, err, tc.refused)
		}
	}
}
