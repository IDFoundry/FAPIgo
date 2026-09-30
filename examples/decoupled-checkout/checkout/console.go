package checkout

import "net/http"

// tourStep is one step of the console's "Start here" walkthrough.
type tourStep struct {
	Title, Do, Notice string
}

var tour = []tourStep{
	{
		Title:  "Pay at the till",
		Do:     "On the till, press Pay with Alder Bank. Open the request on Sam's phone, and approve it.",
		Notice: "The till never sees Sam's credentials: it sent Alder Bank a signed request naming Sam, with the payment as authorization details, then polled. The phone showed the payment from those details, and the bank confirmed the payee's name from its own records. The till then charged exactly what was approved, with a DPoP-bound token.",
	},
	{
		Title:  "Try to misuse the approval",
		Do:     "On the approved order, try each attack button.",
		Notice: "Charging more, or charging twice, is refused by the payments API, which allows only the approved payment, once. Another device holding the token has no DPoP key for it. And an auth_req_id can't be exchanged for tokens a second time.",
	},
	{
		Title:  "A misleading message",
		Do:     "Start a new order with the attack button: €500, which the till's message calls a refund. Look at it on the phone, then deny it.",
		Notice: "CIBA's binding message is free text the client writes. The phone shows it, marked as unchecked, below the payment Alder Bank itself describes from the authorization details: €500 from Sam's account. The till is told the request was declined.",
	},
	{
		Title:  "Link a budgeting app, sharing less",
		Do:     "In Pocketwise, press Link Alder Bank. On the phone, untick the Savings account and standing orders, and approve.",
		Notice: "Pocketwise doesn't poll: the bank pinged it, with the token Pocketwise sent in its request, once Sam decided. Its reads of what Sam unticked are refused by the accounts API; what Sam kept works.",
	},
	{
		Title:  "Ask for more than you're allowed",
		Do:     "In Pocketwise, use the attack button to ask for a payment too.",
		Notice: "Alder Bank lets Pocketwise ask only to read accounts. The request is refused before it reaches Sam's phone.",
	},
}

func (w *World) newConsole() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, _ *http.Request) {
		w.render(rw, "console", consolePage{
			Page: w.page("Decoupled checkout", consoleHost),
			Till: w.URL(tillHost, "/"), Phone: w.URL(phoneHost, "/"), Pocketwise: w.URL(pocketwiseHost, "/"),
			Tour: tour, Log: w.net.Log().Recent(40),
		})
	})
	w.router[consoleHost] = mux
	return nil
}
