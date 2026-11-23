package resource

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/internal/redact"
)

// This file holds the renderings of the requests that carry an access
// token: each prints a shadow (see internal/redact) in which the token
// and the DPoP proofs are [REDACTED]. Their exported fields hold the raw
// values, as Verify needs them: fmt's reflection fallback and the
// encoders print them as they print any exported field, so never log
// the fields.

type verifyRequestShadow struct {
	Method                string
	URL                   string
	Authorization         string
	DPoPProofs            []redact.Hidden
	PeerCertificate       string
	requestPath           string
	repeatedAuthorization bool
}

func (r VerifyRequest) shadow() verifyRequestShadow {
	shadow := verifyRequestShadow{
		Method: r.Method, Authorization: authorizationSummary(r.Authorization), DPoPProofs: redact.MaskStrings(r.DPoPProofs),
		PeerCertificate: certificateSummary(r.PeerCertificate), requestPath: r.requestPath, repeatedAuthorization: r.repeatedAuthorization,
	}
	if r.URL != nil {
		shadow.URL = redact.URL(*r.URL)
	}
	return shadow
}

// authorizationSummary is an Authorization header as a rendering shows
// it: its scheme, Bearer or DPoP in any case, and [REDACTED] for its
// credentials. A header of any other scheme prints as [REDACTED] whole:
// what stands where a malformed header's scheme would, such as a token
// sent with no scheme before it, may be the credential itself.
func authorizationSummary(header string) string {
	if header == "" {
		return ""
	}
	scheme, _, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") && !strings.EqualFold(scheme, "DPoP") {
		return redact.Redacted
	}
	return redact.Name(scheme) + " " + redact.Redacted
}

// certificateSummary is cert as a rendering shows it: its subject, or ""
// for none, %q-quoted if it holds a byte outside printable ASCII (see
// redact.Text). A certificate is public, but its encoding is long, and
// a self-signed one's subject is the client's to choose: a newline in
// it, which pkix.Name's String leaves as it is, would forge a log line.
func certificateSummary(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return redact.Text(cert.Subject.String())
}

// Format implements fmt.Formatter: r prints its method, its URL's
// scheme, host, path and query parameter names, its Authorization
// header's scheme with [REDACTED] for the token, its DPoP proofs as
// [REDACTED] and its certificate as its subject, under every verb and
// flag.
func (r VerifyRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "resource.verifyRequestShadow", "resource.VerifyRequest")
}

// String is r's %v rendering, without its access token or DPoP proofs.
func (r VerifyRequest) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's fields as Format prints them.
func (r VerifyRequest) LogValue() slog.Value {
	shadow := r.shadow()
	return slog.GroupValue(
		slog.String("Method", shadow.Method), slog.String("URL", shadow.URL),
		slog.String("Authorization", shadow.Authorization), slog.Any("DPoPProofs", shadow.DPoPProofs),
		slog.String("PeerCertificate", shadow.PeerCertificate),
	)
}

type resolveAccessTokenRequestShadow struct {
	Raw          redact.Hidden
	Now          time.Time
	MaxClockSkew time.Duration
}

func (r ResolveAccessTokenRequest) shadow() resolveAccessTokenRequestShadow {
	return resolveAccessTokenRequestShadow{Raw: redact.MaskString(r.Raw), Now: r.Now, MaxClockSkew: r.MaxClockSkew}
}

// Format implements fmt.Formatter: r prints its access token as
// [REDACTED], under every verb and flag.
func (r ResolveAccessTokenRequest) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, r.shadow(), "resource.resolveAccessTokenRequestShadow", "resource.ResolveAccessTokenRequest")
}

// String is r's %v rendering, without its access token.
func (r ResolveAccessTokenRequest) String() string { return fmt.Sprint(r.shadow()) }

// LogValue implements slog.LogValuer: r's access token as [REDACTED],
// and its times.
func (r ResolveAccessTokenRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Raw", string(redact.MaskString(r.Raw))), slog.Time("Now", r.Now), slog.Duration("MaxClockSkew", r.MaxClockSkew),
	)
}
