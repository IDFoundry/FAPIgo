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

// requestTargets returns the URLs a DPoP proof's htu may name for req:
// for a request built by VerifyRequestFromHTTP, its escaped path at each
// configured origin whose path prefix covers it; for an explicit
// req.URL, that URL, once it is known to be under one of
// Config.ResourceURLs.
func (v *Verifier) requestTargets(req VerifyRequest) ([]*url.URL, *Error) {
	if req.URL != nil {
		if !req.URL.IsAbs() || req.URL.Host == "" || (req.URL.Scheme != "https" && req.URL.Scheme != "http") {
			return nil, newError(ErrorServerError, 500, "failed to verify request", errors.New("resource: VerifyRequest.URL must be an absolute http(s) URL, or left nil with a request built by VerifyRequestFromHTTP"))
		}
		for _, r := range v.resourceURLs {
			if r.covers(req.URL) {
				return []*url.URL{req.URL}, nil
			}
		}
		return nil, outsideResourceURLs(req.URL.String())
	}
	if !strings.HasPrefix(req.requestPath, "/") {
		return nil, outsideResourceURLs(req.requestPath)
	}
	var targets []*url.URL
	for _, r := range v.resourceURLs {
		t, err := url.Parse(r.origin.String() + req.requestPath)
		if err != nil || t.Host != r.origin.Host || t.RawQuery != "" || t.Fragment != "" {
			continue
		}
		if r.covers(t) {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, outsideResourceURLs(req.requestPath)
	}
	return targets, nil
}

// outsideResourceURLs refuses a request whose target isn't under any of
// Config.ResourceURLs: a handler mounted outside them, or a target an
// adapter built from something the client controls, such as the Host
// header.
func outsideResourceURLs(target string) *Error {
	return newError(ErrorInvalidRequest, 400, "request target is not one of this resource server's URLs", fmt.Errorf("resource: request target %q is not under any of Config.ResourceURLs", target))
}
