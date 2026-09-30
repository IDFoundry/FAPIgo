package payment

import "net/http"

// tourStep is one step of the console's "Start here" walkthrough.
type tourStep struct {
	Title, Do, Notice string
}

var tour = []tourStep{
	{
		Title: "Pay by bank",
		Do:    "Open the shop, press Pay by bank, sign in at Alder Bank as sam (PIN 2468) and approve.",
		Notice: "The shop never sent the payment in the URL. It pushed a signed request object to the bank (PAR) and sent your browser only a request_uri. " +
			"The bank's consent page describes the payment from the request's authorization details, with the payee's name from its own records. " +
			"Its answer came back signed (JARM), and the shop's token is bound to its DPoP key. The order page's protocol trace shows each step decoded.",
	},
	{
		Title: "Misuse the approval",
		Do:    "On the paid order, try each attack button.",
		Notice: "The payments API executes only the approved payment, once. Another device has no DPoP key for the token. " +
			"Redeeming the code again is refused, and revokes the token the first redemption issued. A replayed response has no session left to match, " +
			"and a forged one isn't signed by Alder Bank.",
	},
	{
		Title:  "Tamper with the request",
		Do:     "On the shop's front page, change the amount in the signed request, or send the result to another redirect URI.",
		Notice: "The request object's signature no longer matches, so PAR refuses it. The redirect URI is inside the signed request, and the bank only accepts the one registered for the shop.",
	},
	{
		Title:  "Skip PAR",
		Do:     "Send the payment request straight to the authorization endpoint.",
		Notice: "FAPI 2.0 requires PAR: the authorization endpoint accepts only a request_uri the bank issued for a request it already verified.",
	},
	{
		Title: "Inject someone else's authorization",
		Do:    "Use the injection attack, then open the attacker's response in your browser.",
		Notice: "Alex approved a payment of their own and stopped before returning to the shop. Their response is valid, but it belongs to a checkout " +
			"another browser started: the shop accepts a response only alongside the session cookie of the checkout it answers.",
	},
}

func (w *World) newConsole() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, _ *http.Request) {
		w.render(rw, "console", consolePage{
			Page: w.page("Payment consent", consoleHost), Shop: w.URL(shopHost, "/"),
			Tour: tour, Log: w.net.Log().Recent(40),
		})
	})
	w.router[consoleHost] = mux
}
