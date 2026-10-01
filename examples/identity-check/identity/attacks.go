package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
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
	_ = res.Body.Close()
	claims := append(append([]string{}, rp.setup.idTokenClaims...), rp.setup.userInfoClaims...)
	res, err = post(w.URL(bankHost, authorizePath), url.Values{
		"decision": {"approve"}, "username": {opts.username}, "pin": {opts.pin}, "method": {opts.method}, "claim": claims,
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
	a := attempt{Title: "Ask UserInfo again for the claims " + strings.ToUpper(ck.Username[:1]) + ck.Username[1:] + " withheld"}
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
		return attempt{Title: title, Result: "accepted: verified as " + ck.Username}
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
		return attempt{Title: title, Result: describeError(err), Refused: true}
	}
	return attempt{Title: title, Result: "accepted: UserInfo for " + info.Subject}
}
