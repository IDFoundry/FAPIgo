package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// maxBrowserRedirects bounds the user agent's redirect chain from the
// authorization endpoint through the server's interaction pages and back.
const maxBrowserRedirects = 10

// maxFormSubmissions bounds how many of the server's HTML forms (login,
// consent) the user agent submits in one authorization.
const maxFormSubmissions = 3

// maxPageBytes bounds how much of an HTML page the user agent reads.
const maxPageBytes = 1 << 20

// userAgent stands in for the user's browser: it follows the
// authorization request's redirects with a cookie jar through the
// server's login and consent, and stops at the redirect to redirectURI,
// returning that redirect's query string. The redirect URI itself is
// never requested, as a real client's own callback handler would
// receive it.
//
// A server whose test fixture signs the user in without a page only
// redirects. One that serves its own login or consent page gets its
// form submitted: the run's login_form fields filled in, the form's
// hidden inputs kept, posted to the form's action.
type userAgent struct {
	http      *http.Client
	loginForm map[string]string
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
	return &userAgent{
		http: &http.Client{
			Jar:       jar,
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
		loginForm: rc.LoginForm,
	}, nil
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
	for submitted := 0; ; submitted++ {
		if err != nil {
			return "", err
		}
		if location, locErr := res.Location(); locErr == nil && isCallback(location) {
			_ = res.Body.Close()
			return location.RawQuery, nil
		}
		target, fields, formErr := u.loginFormOn(res, submitted)
		if formErr != nil {
			return "", fmt.Errorf("authorization ended at %s with %d, not a redirect to %s: %w",
				res.Request.URL, res.StatusCode, redirectURI, formErr)
		}
		res, err = browser.PostForm(target, fields)
	}
}

// loginFormOn reads the page res carries and, if it holds a form the
// user agent should submit, returns the form's target and its fields
// filled in from the run's login_form. It closes res's body.
func (u *userAgent) loginFormOn(res *http.Response, submitted int) (string, url.Values, error) {
	page, err := io.ReadAll(io.LimitReader(res.Body, maxPageBytes))
	_ = res.Body.Close()
	if err != nil {
		return "", nil, err
	}
	action, fields, found := parseForm(string(page))
	if !found || u.loginForm == nil || submitted == maxFormSubmissions || res.StatusCode != http.StatusOK {
		return "", nil, errors.New(snippet(page))
	}
	target, err := res.Request.URL.Parse(action)
	if err != nil {
		return "", nil, fmt.Errorf("form action %q: %w", action, err)
	}
	for name, value := range u.loginForm {
		fields.Set(name, value)
	}
	return target.String(), fields, nil
}

var (
	formPattern   = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputPattern  = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	attrPattern   = regexp.MustCompile(`(?is)([a-z_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	spacesPattern = regexp.MustCompile(`\s+`)
)

// parseForm finds the first form on page: its action and its hidden
// inputs' values. A test helper reading the server's own pages, not a
// general HTML parser.
func parseForm(page string) (string, url.Values, bool) {
	form := formPattern.FindStringSubmatch(page)
	if form == nil {
		return "", nil, false
	}
	action, ok := attrs(form[1])["action"]
	if !ok {
		return "", nil, false
	}
	fields := url.Values{}
	for _, input := range inputPattern.FindAllStringSubmatch(form[2], -1) {
		a := attrs(input[1])
		if strings.EqualFold(a["type"], "hidden") && a["name"] != "" {
			fields.Add(a["name"], a["value"])
		}
	}
	return action, fields, true
}

func attrs(tag string) map[string]string {
	out := map[string]string{}
	for _, m := range attrPattern.FindAllStringSubmatch(tag, -1) {
		out[strings.ToLower(m[1])] = html.UnescapeString(m[2] + m[3])
	}
	return out
}

func snippet(page []byte) string {
	s := strings.TrimSpace(spacesPattern.ReplaceAllString(string(page), " "))
	if len(s) > 4096 {
		s = s[:4096]
	}
	return s
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
