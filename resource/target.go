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

	// originKey is canonical.URI(&origin), which a request's
	// requestOrigin is compared to.
	originKey string
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
		origin := url.URL{Scheme: u.Scheme, Host: u.Host}
		out = append(out, resourceURL{
			origin:    origin,
			prefix:    strings.TrimSuffix(canonical.URI(&u), "/"),
			originKey: canonical.URI(&origin),
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
	return v.pathTarget(req.requestPath, req.requestOrigin, dpop)
}

// explicitTarget is target, once it is known to be an absolute http(s)
// URL under one of Config.ResourceURLs.
func (v *Verifier) explicitTarget(target *url.URL) (*url.URL, *Error) {
	if !target.IsAbs() || target.Host == "" || (target.Scheme != "https" && target.Scheme != "http") {
		return nil, newError(ErrorServerError, 500, "failed to verify request", errors.New("resource: VerifyRequest.URL must be an absolute http(s) URL, or left nil with a request built by VerifyRequestFromHTTP"))
	}
	if !canonical.HasNormalPath(target) {
		return nil, nonNormalPath(target.EscapedPath())
	}
	for _, r := range v.resourceURLs {
		if r.covers(target) {
			return target, nil
		}
	}
	return nil, outsideResourceURLs(target.String())
}

// pathTarget resolves escapedPath under the configured prefixes at
// origin (WithResourceOrigin's mark), or at every configured origin for
// none. DPoP needs one unambiguous URI; certificate binding only
// requires a covered path.
func (v *Verifier) pathTarget(escapedPath, origin string, dpop bool) (*url.URL, *Error) {
	if !strings.HasPrefix(escapedPath, "/") {
		return nil, outsideResourceURLs(escapedPath)
	}
	var target *url.URL
	for _, r := range v.resourceURLs {
		if origin != "" && r.originKey != origin {
			continue
		}
		t, covered, perr := r.pathAt(escapedPath)
		if perr != nil {
			return nil, perr
		}
		if !covered {
			continue
		}
		if target != nil && dpop && canonical.URI(target) != canonical.URI(t) {
			return nil, ambiguousTarget(escapedPath)
		}
		target = t
	}
	if target == nil {
		return nil, v.uncoveredPath(escapedPath, origin)
	}
	return target, nil
}

// pathAt is escapedPath at r's origin, and whether r covers it there.
// A path not in normal form is refused whichever origin it is at.
func (r resourceURL) pathAt(escapedPath string) (*url.URL, bool, *Error) {
	t, err := url.Parse(r.origin.String() + escapedPath)
	if err != nil {
		return nil, false, nil
	}
	if !canonical.HasNormalPath(t) {
		return nil, false, nonNormalPath(escapedPath)
	}
	return t, t.Host == r.origin.Host && t.RawQuery == "" && t.Fragment == "" && r.covers(t), nil
}

// ambiguousTarget refuses a DPoP request whose path is covered at more
// than one configured origin, with nothing to say which it was received
// at: the deployment's to fix, so a 500.
func ambiguousTarget(escapedPath string) *Error {
	return newError(ErrorServerError, 500, "ambiguous DPoP request target", fmt.Errorf("resource: several of Config.ResourceURLs' origins cover the request path %q: wrap the listener's handler in resource.WithResourceOrigin, or set VerifyRequest.URL, from the listener or a trusted proxy route (never the Host header)", escapedPath))
}

// uncoveredPath refuses a request no configured prefix at origin covers:
// outsideResourceURLs, unless no ResourceURLs entry is at origin at all,
// so that WithResourceOrigin marks the listener with an origin this
// resource server doesn't serve, which is the deployment's to fix.
func (v *Verifier) uncoveredPath(escapedPath, origin string) *Error {
	if origin == "" {
		return outsideResourceURLs(escapedPath)
	}
	for _, r := range v.resourceURLs {
		if r.originKey == origin {
			return outsideResourceURLs(escapedPath)
		}
	}
	return newError(ErrorServerError, 500, "failed to verify request", fmt.Errorf("resource: resource.WithResourceOrigin marks the request with origin %q, which none of Config.ResourceURLs is at", origin))
}

// nonNormalPath refuses a request whose path isn't in the normal form
// a DPoP htu is compared in: one with a dot segment ("/a/../b") or a
// percent-encoded unreserved character ("/accounts/%31"). htu matching
// resolves both, so the proof would match, while a router that
// dispatches on the path as sent would run a different handler from
// the one the proof names. A client building its URL from the resource
// server's own does not send such a path.
func nonNormalPath(escapedPath string) *Error {
	return newError(ErrorInvalidRequest, 400, "request path is not in normal form", fmt.Errorf("resource: request path %q has a dot segment or a percent-encoded unreserved character", escapedPath))
}

// outsideResourceURLs refuses a request whose target isn't under any of
// Config.ResourceURLs: a handler mounted outside them, or a target an
// adapter built from something the client controls, such as the Host
// header.
func outsideResourceURLs(target string) *Error {
	return newError(ErrorInvalidRequest, 400, "request target is not one of this resource server's URLs", fmt.Errorf("resource: request target %q is not under any of Config.ResourceURLs", target))
}
