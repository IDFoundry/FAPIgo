package payroll

import "net/http"

// tourStep is one step of the console's "Start here" walkthrough.
type tourStep struct {
	Title, Do, Notice string
}

var tour = []tourStep{
	{
		Title: "Run payroll",
		Do:    "Open Ledgerline and press Run payroll.",
		Notice: "Nobody signs in. Ledgerline's connection to the bank's token endpoint presents its TLS client certificate, which is how it authenticates: " +
			"the bank checks that its client CA issued it, that it hasn't been revoked, and that its subject is the one registered for Ledgerline. " +
			"The token it issues carries the certificate's thumbprint (cnf.x5t#S256), and grants exactly this batch from Harbour Coffee's account, " +
			"which Harbour Coffee's mandate allows. The run page's protocol trace shows the certificate presented and the token decoded.",
	},
	{
		Title: "Steal the token",
		Do:    "On the paid run, try each attack.",
		Notice: "The payroll API accepts the token only over a connection presenting the certificate it's bound to: without one, or with " +
			"Copperfield's perfectly valid certificate, it's refused. With the right certificate, the API still pays only the granted batch, once.",
	},
	{
		Title: "Get a token without Ledgerline's key",
		Do:    "Back on Ledgerline's page, try each attack at the token endpoint.",
		Notice: "A certificate naming Ledgerline proves nothing on its own: a self-signed one, or one from another CA calling itself Alder Bank's, " +
			"doesn't chain to the bank's client CA. Ledgerline's expired certificate has run out, and its earlier certificate whose key leaked is " +
			"on the bank's revocation list. Copperfield's certificate is valid, but its subject isn't the one registered for Ledgerline.",
	},
	{
		Title:  "Exceed the mandate",
		Do:     "Ask for a token to pay from Brightwater Bakery's account, or for a batch over the mandate's limit.",
		Notice: "With no end user to approve each batch, the bank decides from Harbour Coffee's standing mandate (its client credentials RAR policy), and refuses the token outright.",
	},
	{
		Title: "Rotate the certificate",
		Do:    "Rotate Ledgerline's certificate.",
		Notice: "The new certificate has the same subject, so Ledgerline's registration doesn't change and new tokens are issued straight away. " +
			"A token issued before the rotation is bound to the old certificate, though, so it's refused with the new one: tokens follow the certificate, not the client.",
	},
}

func (w *World) newConsole() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, _ *http.Request) {
		w.render(rw, "console", consolePage{
			Page: w.page("Payroll run", consoleHost), Ledgerline: w.URL(ledgerlineHost, "/"),
			Tour: tour, Log: w.net.Log().Recent(40),
		})
	})
	w.router[consoleHost] = mux
}
