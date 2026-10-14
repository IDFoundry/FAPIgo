package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server/interactioncookie"
)

// captures is what the attack lab captured from other sign-ins, as it
// crossed the wire: Alex's ID token and UserInfo response for Fernway,
// and Brightline's ID token for Sam.
type captures struct {
	mu                                           sync.Mutex
	alexIDToken, alexUserInfo, brightlineIDToken string
}

// The attack lab's ID token swaps: the scenario values its buttons post.
const (
	swapAlex       = "swap-alex"
	swapBrightline = "swap-brightline"
)

func (c *captures) idTokenFor(scenario string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch scenario {
	case swapAlex:
		return c.alexIDToken
	case swapBrightline:
		return c.brightlineIDToken
	}
	return ""
}

// capture runs the sign-ins the attack lab replays, once: Alex verifying
// with Fernway, and Sam with Brightline.
func (w *World) capture(ctx context.Context) error {
	w.captured.mu.Lock()
	done := w.captured.alexIDToken != "" && w.captured.brightlineIDToken != ""
	w.captured.mu.Unlock()
	if done {
		return nil
	}
	alex, err := w.signIn(ctx, w.fernway, signInOptions{username: "alex", pin: "1357", method: "app", scenario: "normal"})
	if err != nil {
		return fmt.Errorf("the replayed sign-in by alex at Fernway: %w", err)
	}
	sam, err := w.signIn(ctx, w.brightline, signInOptions{username: "sam", pin: "2468", method: "app", scenario: "normal"})
	if err != nil {
		return fmt.Errorf("the replayed sign-in by sam at Brightline: %w", err)
	}
	alexIDToken, alexUserInfo := alex.wire.get()
	brightlineIDToken, _ := sam.wire.get()
	if alexIDToken == "" || alexUserInfo == "" || brightlineIDToken == "" {
		return errors.New("the sign-ins to replay didn't complete")
	}
	w.captured.mu.Lock()
	defer w.captured.mu.Unlock()
	w.captured.alexIDToken, w.captured.alexUserInfo, w.captured.brightlineIDToken = alexIDToken, alexUserInfo, brightlineIDToken
	return nil
}

// interactionTag finds the consent form's interactioncookie tag.
var interactionTag = regexp.MustCompile(`name="` + interactioncookie.FormField + `" value="([^"]*)"`)

// signInOptions is how a scripted browser goes through an identity
// check.
type signInOptions struct {
	username, pin, method, scenario string
}

// signIn drives a fresh browser through rp's identity check: start it,
// sign in at the bank the way opts says, approve every requested claim,
// and return the check it ends on.
func (w *World) signIn(ctx context.Context, rp *relyingParty, opts signInOptions) (*check, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	device := w.net.Browser(jar)
	post := func(target string, form url.Values) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return device.Do(req)
	}
	res, err := post(w.URL(rp.setup.host, "/start"), url.Values{"scenario": {opts.scenario}})
	if err != nil {
		return nil, err
	}
	// The bank's consent page: its form carries the tag that ties the
	// submission to this browser's interaction cookie.
	consent, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	tag := interactionTag.FindSubmatch(consent)
	if tag == nil {
		return nil, fmt.Errorf("the sign-in didn't reach the bank's consent page (%s)", res.Request.URL)
	}
	claims := append(append([]string{}, rp.setup.idTokenClaims...), rp.setup.userInfoClaims...)
	res, err = post(w.URL(bankHost, authorizePath), url.Values{
		interactioncookie.FormField: {string(tag[1])},
		"decision":                  {"approve"}, "username": {opts.username}, "pin": {opts.pin}, "method": {opts.method}, "claim": claims,
	})
	if err != nil {
		return nil, err
	}
	_ = res.Body.Close()
	id := res.Request.URL.Query().Get("id")
	ck, ok := rp.lookup(id)
	if !ok {
		return nil, fmt.Errorf("the sign-in ended at %s, not on an identity check", res.Request.URL)
	}
	rp.mu.Lock()
	ck.lab = true
	rp.mu.Unlock()
	return ck, nil
}

// attack tries to get around one of the identity check's protections,
// using the verified check's tokens or the sign-ins the lab captured.
func (rp *relyingParty) attack(w http.ResponseWriter, r *http.Request) {
	ck, ok := rp.lookup(r.FormValue("id"))
	if !ok || ck.Status != "verified" {
		rp.w.renderError(w, rp.setup.host, http.StatusBadRequest, "No verified identity check", "These attacks need a completed identity check.")
		return
	}
	ctx := r.Context()
	var a attempt
	switch r.FormValue("kind") {
	case "withheld":
		a = rp.askAgain(ctx, ck)
	case "eavesdrop":
		a = rp.eavesdrop(ck)
	case swapAlex:
		a = rp.replay(ctx, "Swap in Alex's ID token", swapAlex)
	case swapBrightline:
		a = rp.replay(ctx, "Swap in the ID token Alder Bank gave Brightline", swapBrightline)
	case "other-userinfo":
		a = rp.userInfoAttempt(ctx, "Swap in Alex's UserInfo response", rp.client, ck, func(o *traceOptions) error {
			if err := rp.w.capture(ctx); err != nil {
				return err
			}
			rp.w.captured.mu.Lock()
			o.userInfo = []byte(rp.w.captured.alexUserInfo)
			rp.w.captured.mu.Unlock()
			return nil
		})
	case "tamper-userinfo":
		a = rp.userInfoAttempt(ctx, "Tamper with the UserInfo response", rp.client, ck, func(o *traceOptions) error {
			o.tamperUserInfo = true
			return nil
		})
	case "stolen":
		a = rp.userInfoAttempt(ctx, "Use the access token from another device", rp.thief, ck, nil)
	case "hint-other-rp":
		a = rp.hintFromOtherRP(ctx)
	case "sub-from-other-rp":
		a = rp.subFromOtherRP(ctx, ck)
	case "forge-sub":
		a = rp.userInfoAttempt(ctx, "Change the access token's sub to the one Brightline knows you by", rp.client, ck, func(o *traceOptions) error {
			sub, err := rp.w.brightlineSub(ctx)
			o.accessTokenSub = sub
			return err
		})
	default:
		rp.w.renderError(w, rp.setup.host, http.StatusBadRequest, "Unknown attack", r.FormValue("kind"))
		return
	}
	rp.mu.Lock()
	ck.Attempts = append(ck.Attempts, a)
	rp.mu.Unlock()
	http.Redirect(w, r, checkURL(ck.ID)+"#attempts", http.StatusSeeOther)
}

// askAgain calls UserInfo again with the check's own token: the bank
// still returns only what the customer approved.
func (rp *relyingParty) askAgain(ctx context.Context, ck *check) attempt {
	a := attempt{Title: "Ask UserInfo again for the claims you withheld"}
	c, err := rp.client.get(ctx)
	if err != nil {
		return attempt{Title: a.Title, Result: err.Error(), Refused: true}
	}
	info, err := c.FetchUserInfo(withTrace(ctx, traceOptions{trace: &trace{}}), ck.tokens)
	if err != nil {
		return attempt{Title: a.Title, Result: describeError(err), Refused: true}
	}
	got := userInfoNames(info)
	var withheld []string
	for _, name := range rp.setup.userInfoClaims {
		if _, ok := info.Parameters[name]; !ok {
			withheld = append(withheld, name)
		}
	}
	a.Refused = len(withheld) > 0
	a.Result = fmt.Sprintf("UserInfo returned: %s\nstill withheld: %s", list(got), list(withheld))
	if !a.Refused {
		a.Result += "\n(nothing was withheld: untick a claim at the bank to try this)"
		a.Refused = true
	}
	return a
}

func list(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// eavesdrop is what someone watching the token response would see.
func (rp *relyingParty) eavesdrop(ck *check) attempt {
	idToken, userInfo := ck.wire.get()
	encrypted := strings.Count(idToken, ".") == 4 && strings.Count(userInfo, ".") == 4
	return attempt{
		Title:   "Read the claims off the wire",
		Refused: encrypted,
		Result:  "The ID token, as it crossed the wire:\n" + describeJOSE(idToken) + "\n\nThe UserInfo response:\n" + describeJOSE(userInfo),
	}
}

// replay runs a new identity check for Sam with the bank's ID token
// replaced in flight by one the lab captured from another sign-in.
func (rp *relyingParty) replay(ctx context.Context, title, scenario string) attempt {
	if err := rp.w.capture(ctx); err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	ck, err := rp.w.signIn(ctx, rp, signInOptions{username: "sam", pin: "2468", method: "app", scenario: scenario})
	if err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if ck.Status == "verified" {
		return attempt{Title: title, Result: "accepted: verified as " + ck.Sub}
	}
	return attempt{Title: title, Result: ck.Problem, Refused: true}
}

// userInfoAttempt fetches UserInfo with the check's token through lc,
// after setup has set up the in-flight substitution.
func (rp *relyingParty) userInfoAttempt(ctx context.Context, title string, lc *lazyClient, ck *check, setup func(*traceOptions) error) attempt {
	opts := traceOptions{trace: &trace{}}
	if setup != nil {
		if err := setup(&opts); err != nil {
			return attempt{Title: title, Result: err.Error(), Refused: true}
		}
	}
	c, err := lc.get(ctx)
	if err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	info, err := c.FetchUserInfo(withTrace(ctx, opts), ck.tokens)
	if err != nil {
		return attempt{Title: title, Result: describeError(err) + bankAnswer(opts.trace), Refused: true}
	}
	return attempt{Title: title, Result: "accepted: UserInfo for " + info.Subject}
}

// errorMember finds an OAuth error response's members in a trace step.
var errorMember = regexp.MustCompile(`"(error|error_description)": "([^"]*)"`)

// bankAnswer is the OAuth error Alder Bank answered the last request in
// t with, when there is one: what a bare HTTP status doesn't say.
func bankAnswer(t *trace) string {
	steps := t.Steps()
	if len(steps) == 0 {
		return ""
	}
	members := map[string]string{}
	for _, m := range errorMember.FindAllStringSubmatch(steps[len(steps)-1].Detail, -1) {
		members[m[1]] = m[2]
	}
	if members["error"] == "" {
		return ""
	}
	return "\nAlder Bank answered " + members["error"] + ": " + members["error_description"]
}

// Authorization parameters the attack lab sends as they are, through the
// FAPIgo client's Extensions: a well-behaved relying party would ask for
// these through the bank's own flow, not with someone else's values.
var (
	idTokenHintParam = extension.Definition[string]{
		Name: "id_token_hint", Cardinality: extension.Single, AllowedSources: extension.SourcePlainParameter,
		MaxBytes: 8 << 10, Sensitivity: extension.NotSensitive,
	}
	claimsParam = extension.Definition[string]{
		Name: "claims", Cardinality: extension.Single, AllowedSources: extension.SourcePlainParameter,
		MaxBytes: 1 << 10, Sensitivity: extension.NotSensitive,
	}
)

// hintFromOtherRP has Fernway name the customer to sign in with the ID
// token Alder Bank gave Brightline for Sam, as an id_token_hint (OIDC
// Core §3.1.2.1). Relying parties comparing notes could pass one to
// another; the bank accepts a hint only from the client it was issued
// to.
func (rp *relyingParty) hintFromOtherRP(ctx context.Context) attempt {
	const title = "Name you with the ID token Brightline got for you (id_token_hint)"
	if err := rp.w.capture(ctx); err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	rp.w.captured.mu.Lock()
	hint := rp.w.captured.brightlineIDToken
	rp.w.captured.mu.Unlock()
	req := client.BeginAuthorizationRequest{Scope: []string{"openid"}}
	return rp.beginWith(ctx, title, rp.client, req, idTokenHintParam, hint)
}

// subFromOtherRP has Brightline ask the bank to sign in the customer
// Fernway knows by sub: a "claims" request for that sub value (OIDC Core
// §5.5.1). Under pairwise subs, that sub means nothing at Brightline.
func (rp *relyingParty) subFromOtherRP(ctx context.Context, ck *check) attempt {
	const title = "Brightline asks the bank for the customer Fernway knows by your sub"
	claims, err := json.Marshal(map[string]any{"id_token": map[string]any{"sub": map[string]string{"value": ck.Sub}}})
	if err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	req := client.BeginAuthorizationRequest{Scope: []string{"openid"}}
	return rp.beginWith(ctx, title, rp.w.brightline.client, req, claimsParam, string(claims))
}

// beginWith pushes req, with param set to value, through lc's client,
// and reports whether the bank accepted it.
func (rp *relyingParty) beginWith(ctx context.Context, title string, lc *lazyClient, req client.BeginAuthorizationRequest, param extension.Definition[string], value string) attempt {
	c, err := lc.get(ctx)
	if err == nil {
		err = extension.Set(&req.Extensions, param, value)
	}
	if err != nil {
		return attempt{Title: title, Result: err.Error(), Refused: true}
	}
	if _, err := c.BeginAuthorization(withTrace(ctx, traceOptions{trace: &trace{}}), req); err != nil {
		return attempt{Title: title, Result: "Alder Bank refused the pushed authorization request: " + describeError(err), Refused: true}
	}
	return attempt{Title: title, Result: "accepted: the bank took the request"}
}

// brightlineSub is the sub Alder Bank gave Brightline for Sam, read from
// the ID token the lab captured from Sam's sign-in there.
func (w *World) brightlineSub(ctx context.Context) (string, error) {
	if err := w.capture(ctx); err != nil {
		return "", err
	}
	w.captured.mu.Lock()
	idToken := w.captured.brightlineIDToken
	w.captured.mu.Unlock()
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("the captured Brightline ID token isn't a signed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Sub == "" {
		return "", errors.New("the captured Brightline ID token has no sub")
	}
	return claims.Sub, nil
}
