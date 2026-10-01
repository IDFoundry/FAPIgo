package identity

import "net/http"

// tourStep is one step of the console's "Start here" walkthrough.
type tourStep struct {
	Title, Do, Notice string
}

var tour = []tourStep{
	{
		Title: "Verify with Alder Bank",
		Do:    "Open Fernway, press Verify with Alder Bank, sign in as sam (PIN 2468) with the app, and share everything.",
		Notice: "Fernway pushed its request to the bank (PAR) with a claims parameter naming exactly what it needs, acr_values asking for an app-approved sign-in and max_age asking for a recent one. " +
			"The ID token and the UserInfo response came back signed by the bank and encrypted to Fernway: the protocol trace shows what an observer on the wire could read, which is only the encryption headers.",
	},
	{
		Title:  "Share less",
		Do:     "Start again, untick your address and phone number at the bank, then use Ask UserInfo again for withheld claims.",
		Notice: "The bank releases only what you approved. The access token remembers which UserInfo claims that was, so asking again with it gets nothing more.",
	},
	{
		Title: "Sign in too weakly, or too long ago",
		Do:    "Start again and pick PIN only. Then start again and pick your earlier sign-in.",
		Notice: "acr_values is a request: the bank signs you in with a PIN alone and says so in the ID token's acr, and Fernway refuses it. " +
			"max_age is a requirement: an earlier sign-in is too old, so the bank itself answers Fernway with login_required instead of an authorization code.",
	},
	{
		Title: "Attack the verified check",
		Do:    "On a verified check, try each attack.",
		Notice: "Someone else's ID token, even one the bank issued, doesn't belong to this sign-in: Alex's carries another nonce, and Brightline's wasn't encrypted to Fernway, as Fernway registered for. Alex's UserInfo response is genuine but names another subject. " +
			"A tampered response no longer decrypts. A stolen access token is bound to Fernway's DPoP key.",
	},
	{
		Title:  "Compare Brightline Rentals",
		Do:     "Open Brightline Rentals and verify there too.",
		Notice: "It asks for less, needs no particular sign-in, and receives its ID token signed but not encrypted: whatever a relying party registers for, the customer still decides what's released.",
	},
}

func (w *World) newConsole() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, _ *http.Request) {
		w.render(rw, "console", consolePage{
			Page: w.page("Identity check", consoleHost), Fernway: w.URL(fernwayHost, "/"), Brightline: w.URL(brightlineHost, "/"),
			Tour: tour, Log: w.net.Log().Recent(40),
		})
	})
	w.router[consoleHost] = mux
}
