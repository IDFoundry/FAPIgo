package linked

import (
	"net/http"
	"strconv"
	"time"
)

// tourStep is one step of the console's "Start here" walkthrough.
type tourStep struct {
	Title, Do, Notice string
}

var tour = []tourStep{
	{
		Title: "Link your accounts",
		Do:    "Open Pocketwise, press Link Alder Bank accounts, sign in as sam (PIN 2468), choose which accounts to share, and approve.",
		Notice: "Pocketwise asked for offline_access and an account_access Rich Authorization Request without naming accounts, so you chose them at the bank. " +
			"The bank recorded the approval under a grant ID, and Pocketwise received a refresh token valid for 90 days alongside a short-lived, DPoP-bound access token.",
	},
	{
		Title: "Sync without you",
		Do:    "Press Sync now a few times, rotate Pocketwise's DPoP key, and sync again. Fast-forward the clock by a day between syncs.",
		Notice: "Each sync redeems the refresh token, authenticating as Pocketwise, for a new access token. The refresh token itself comes back unchanged: FAPI 2.0 servers don't rotate refresh tokens. " +
			"After the key rotation, the new access token is bound to the new DPoP key.",
	},
	{
		Title:  "Misuse the long-lived access",
		Do:     "Try each attack in Pocketwise's attack lab.",
		Notice: "The refresh token belongs to Pocketwise: Thriftly, a genuine client of the bank, can't redeem it, and nobody can without authenticating as Pocketwise. A refresh can narrow the scope but never widen it. The access token is bound to Pocketwise's DPoP key.",
	},
	{
		Title: "Withdraw Pocketwise's access",
		Do:    "Open Alder Bank's Connected apps, revoke Pocketwise, then sync in Pocketwise.",
		Notice: "Revoking calls RevokeGrant with the grant ID the bank stored when you approved. The next refresh is refused with invalid_grant, and the access token Pocketwise still holds is refused by the API too: " +
			"every token from the grant carries its grant_id.",
	},
	{
		Title:  "Let the consent run out",
		Do:     "Link again, then fast-forward the clock by 91 days and sync.",
		Notice: "The refresh token expires 90 days after it was issued, and refreshing doesn't extend it. Pocketwise has to ask you again.",
	},
}

func (w *World) newConsole() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, _ *http.Request) {
		w.render(rw, "console", consolePage{
			Page: w.page("Linked accounts", consoleHost), Pocketwise: w.URL(pocketwiseHost, "/"),
			ConnectedApps: w.URL(bankHost, connectedAppsPath), DaysAhead: w.clock.daysAhead(),
			Tour: tour, Log: w.net.Log().Recent(40),
		})
	})
	mux.Handle("POST /clock", http.NewCrossOriginProtection().Handler(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		days, err := strconv.Atoi(r.FormValue("days"))
		if err != nil || days < 1 || days > 365 {
			w.renderError(rw, consoleHost, http.StatusBadRequest, "Can't move the clock", "Choose a number of days.")
			return
		}
		w.clock.advance(time.Duration(days) * 24 * time.Hour)
		http.Redirect(rw, r, "/", http.StatusSeeOther)
	})))
	w.router[consoleHost] = mux
}
