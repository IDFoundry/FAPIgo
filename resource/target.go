package resource

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/idfoundry/fapigo/internal/canonical"
)

// resourceURL is one of Config.ResourceURLs, prepared for matching: its
// origin, which a request's path is appended to, and its canonical form
// (canonical.URI) without a trailing "/", which a target must equal or
// extend by a "/" and further segments.
type resourceURL struct {
	origin url.URL
	prefix string
}

// prepareResourceURLs checks Config.ResourceURLs and prepares each for
// matching.
func prepareResourceURLs(cfg Config) ([]resourceURL, error) {
	if len(cfg.ResourceURLs) == 0 {
		return nil, errors.New("resource: config: resource_urls is required: this resource server's own external URLs (origins, optionally with a path prefix), which a DPoP proof's htu must name")
	}
	out := make([]resourceURL, 0, len(cfg.ResourceURLs))
	for i, ru := range cfg.ResourceURLs {
		if ru.IsZero() {
			return nil, fmt.Errorf("resource: config: resource_urls[%d] is unset", i)
		}
		u := ru.URL()
		switch {
		case u.Scheme == "http" && cfg.Assurance == AssuranceProduction:
			return nil, fmt.Errorf("resource: config: resource_urls[%d] was parsed with fapi.AllowLoopbackHTTP, which is not permitted under AssuranceProduction", i)
		case u.RawQuery != "" || u.ForceQuery:
			return nil, fmt.Errorf("resource: config: resource_urls[%d] must not have a query: it is an origin, optionally with a path prefix", i)
		case !canonical.HasNormalPath(&u):
			return nil, fmt.Errorf("resource: config: resource_urls[%d] has a path with dot segments or percent-encoded unreserved characters", i)
		}
		out = append(out, resourceURL{
			origin: url.URL{Scheme: u.Scheme, Host: u.Host},
			prefix: strings.TrimSuffix(canonical.URI(&u), "/"),
		})
	}
	return out, nil
}

// covers reports whether target, an absolute URL, is at r's origin and
// under its path prefix, once canonicalized as a DPoP htu is.
func (r resourceURL) covers(target *url.URL) bool {
	c := canonical.URI(target)
	return c == r.prefix || strings.HasPrefix(c, r.prefix+"/")
}

// requestTarget checks an explicit target or resolves the received path
// against the configured origins.
func (v *Verifier) requestTarget(req VerifyRequest, dpop bool) (*url.URL, *Error) {
	if req.URL != nil {
		return v.explicitTarget(req.URL)
	}
	return v.pathTarget(req.requestPath, dpop)
}

// explicitTarget is target, once it is known to be an absolute http(s)
// URL under one of Config.ResourceURLs.
func (v *Verifier) explicitTarget(target *url.URL) (*url.URL, *Error) {
	if !target.IsAbs() || target.Host == "" || (target.Scheme != "https" && target.Scheme != "http") {
		return nil, newError(ErrorServerError, 500, "failed to verify request", errors.New("resource: VerifyRequest.URL must be an absolute http(s) URL, or left nil with a request built by VerifyRequestFromHTTP"))
	}
	for _, r := range v.resourceURLs {
		if r.covers(target) {
			return target, nil
		}
	}
	return nil, outsideResourceURLs(target.String())
}

// pathTarget resolves escapedPath under the configured prefixes. DPoP needs
// one unambiguous URI. Certificate binding only requires a covered path.
func (v *Verifier) pathTarget(escapedPath string, dpop bool) (*url.URL, *Error) {
	if !strings.HasPrefix(escapedPath, "/") {
		return nil, outsideResourceURLs(escapedPath)
	}
	var target *url.URL
	for _, r := range v.resourceURLs {
		t, err := url.Parse(r.origin.String() + escapedPath)
		if err == nil && t.Host == r.origin.Host && t.RawQuery == "" && t.Fragment == "" && r.covers(t) {
			if target != nil && dpop && canonical.URI(target) != canonical.URI(t) {
				return nil, newError(ErrorServerError, 500, "ambiguous DPoP request target", errors.New("set VerifyRequest.URL from trusted routing metadata when multiple resource origins cover the request path"))
			}
			target = t
		}
	}
	if target == nil {
		return nil, outsideResourceURLs(escapedPath)
	}
	return target, nil
}

// outsideResourceURLs refuses a request whose target isn't under any of
// Config.ResourceURLs: a handler mounted outside them, or a target an
// adapter built from something the client controls, such as the Host
// header.
func outsideResourceURLs(target string) *Error {
	return newError(ErrorInvalidRequest, 400, "request target is not one of this resource server's URLs", fmt.Errorf("resource: request target %q is not under any of Config.ResourceURLs", target))
}
