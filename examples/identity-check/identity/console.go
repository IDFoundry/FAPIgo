package identity

import (
	"net/http"
	"sort"
)

// tourStep is one step of the console's "Start here" walkthrough.
type tourStep struct {
	Title, Do, Notice string
}

var tour = []tourStep{
	{
		Title: "Verify with Alder Bank",
		Do:    "Open Fernway, press Verify with Alder Bank, sign in as sam (PIN 2468) with the app, and share everything.",
		Notice: "Fernway pushed its request to the bank (PAR) with a claims parameter naming exactly what it needs, acr_values asking for an app-approved sign-in and max_age asking for a recent one. " +
			"The ID token and the UserInfo response came back signed by the bank and encrypted to Fernway: the protocol trace shows what an observer on the wire could read, which is only the encryption headers. " +
			"Fernway's page shows the sub the bank gave it for you: not your username but a pairwise sub (OpenID Connect Core §8), Fernway's alone.",
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
			"A tampered response no longer decrypts. A stolen access token is bound to Fernway's DPoP key. " +
			"Your sub at one relying party is no use at another: the bank accepts an id_token_hint only from the client it issued that ID token to, a sub Fernway knows means nothing when Brightline asks for it, and an access token whose sub is changed no longer matches the DPoP proof bound to it.",
	},
	{
		Title: "Compare Brightline Rentals",
		Do:    "Open Brightline Rentals and verify there too.",
		Notice: "It asks for less, needs no particular sign-in, and receives its ID token signed but not encrypted: whatever a relying party registers for, the customer still decides what's released. " +
			"It also knows you by a different sub from Fernway's.",
	},
	{
		Title: "Compare what they know",
		Do:    "With a check at both, look at What each relying party knows below, and If they compare notes. Then look at What Alder Bank's UserInfo endpoint saw.",
		Notice: "Joining their records on sub finds nobody in common. Joining on email links you, if you released your email to both: pairwise subs hide only the sub, not the claims you share. " +
			"To see it fail, start the demo again and untick your email at one of them. The bank's UserInfo endpoint maps each relying party's sub back to you to look up your claims, and answers with that relying party's own sub.",
	},
}

func (w *World) newConsole() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, _ *http.Request) {
		fernway, brightline := w.fernway.knownCustomers(), w.brightline.knownCustomers()
		w.render(rw, "console", consolePage{
			Page: w.page("Identity check", consoleHost), Fernway: w.URL(fernwayHost, "/"), Brightline: w.URL(brightlineHost, "/"),
			Tour: tour, Log: w.net.Log().Recent(40),
			Known:         []rpKnowledge{{Name: fernwaySetup.name, Customers: fernway}, {Name: brightlineSetup.name, Customers: brightline}},
			Comparison:    compareNotes(fernway, brightline),
			UserInfoCalls: w.bank.recentUserInfoCalls(),
		})
	})
	w.router[consoleHost] = mux
}

// knownCustomer is one customer as a relying party knows them: by the
// sub Alder Bank gave it, with the claims it was given.
type knownCustomer struct {
	Sub, Name, Email string
	SignIns          int
}

// rpKnowledge is everything one relying party knows about its customers.
type rpKnowledge struct {
	Name      string
	Customers []knownCustomer
}

// knownCustomers is this relying party's customers, from the identity
// checks made in the browser (not the attack lab's), one per sub, with
// the newest name and any email the customer ever released to it.
func (rp *relyingParty) knownCustomers() []knownCustomer {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	bySub := map[string]*knownCustomer{}
	var order []string
	for _, ck := range rp.checks {
		if ck.Status != "verified" || ck.lab {
			continue
		}
		k, ok := bySub[ck.Sub]
		if !ok {
			k = &knownCustomer{Sub: ck.Sub}
			bySub[ck.Sub] = k
			order = append(order, ck.Sub)
		}
		k.SignIns++
		if ck.Name != "" {
			k.Name = ck.Name
		}
		if ck.Email != "" {
			k.Email = ck.Email
		}
	}
	sort.Strings(order)
	out := make([]knownCustomer, 0, len(order))
	for _, sub := range order {
		out = append(out, *bySub[sub])
	}
	return out
}

// comparison is what Fernway and Brightline learn by comparing their
// customer records: what they can join on.
type comparison struct {
	// Ready is whether both have a customer to compare.
	Ready bool
	// SameSub is customers they know by the same sub: none, with
	// pairwise subs.
	SameSub []string
	// SameEmail is customers they can link by an email address both were
	// given: what pairwise subs can't prevent.
	SameEmail []emailLink
}

type emailLink struct{ Email, FernwaySub, BrightlineSub string }

func compareNotes(fernway, brightline []knownCustomer) comparison {
	c := comparison{Ready: len(fernway) > 0 && len(brightline) > 0}
	for _, f := range fernway {
		for _, b := range brightline {
			if f.Sub == b.Sub {
				c.SameSub = append(c.SameSub, f.Sub)
			}
			if f.Email != "" && f.Email == b.Email {
				c.SameEmail = append(c.SameEmail, emailLink{Email: f.Email, FernwaySub: f.Sub, BrightlineSub: b.Sub})
			}
		}
	}
	return c
}
