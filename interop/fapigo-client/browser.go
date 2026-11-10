package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// maxBrowserRedirects bounds the user agent's redirect chain from the
// authorization endpoint through the server's interaction pages and back.
const maxBrowserRedirects = 10

// userAgent stands in for the user's browser: it follows the
// authorization request's redirects with a cookie jar through the
// server's (headless) login and consent, and stops at the redirect to
// redirectURI, returning that redirect's query string. The redirect
// URI itself is never requested, as a real client's own callback
// handler would receive it.
type userAgent struct {
	http *http.Client
}

func newUserAgent(rc runConfig) (*userAgent, error) {
	roots, err := loadCAPool(rc.CAFile)
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &userAgent{http: &http.Client{
		Jar:       jar,
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}}, nil
}

func (u *userAgent) authorize(authorizationURL, redirectURI string) (string, error) {
	callback, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect URI: %w", err)
	}
	isCallback := func(target *url.URL) bool {
		return target.Scheme == callback.Scheme && target.Host == callback.Host && target.Path == callback.Path
	}
	browser := *u.http
	browser.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if isCallback(req.URL) {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxBrowserRedirects {
			return errors.New("too many redirects")
		}
		return nil
	}

	res, err := browser.Get(authorizationURL)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	location, err := res.Location()
	if err != nil || !isCallback(location) {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", fmt.Errorf("authorization ended at %s with %d, not a redirect to %s: %s",
			res.Request.URL, res.StatusCode, redirectURI, strings.TrimSpace(string(body)))
	}
	return location.RawQuery, nil
}

// post sends form to target as the test environment's own HTTP client
// (the CIBA approval hook), trusting the run's CA.
func (u *userAgent) post(target string, form url.Values) error {
	res, err := u.http.PostForm(target, form)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("%s returned %d: %s", target, res.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
