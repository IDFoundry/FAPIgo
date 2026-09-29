package union

import (
	"net/url"
	"sync/atomic"
)

// scene is one console switch that changes how the federation behaves.
type scene struct {
	key, title, description string
	flag                    *atomic.Bool
}

// sceneList is every scene, in the order the tour reaches them.
func (w *World) sceneList() []scene {
	s := &w.scenes
	return []scene{
		{key: "forge", title: "EastID forges its assurance mark", flag: &s.ForgeEastmarkMark,
			description: "EastID publishes a level-of-assurance Trust Mark it signed itself. It verifies as a signature — EastID is a federation member — but the Union doesn't accredit EastID to issue it, so services refuse it."},
		{key: "suspend", title: "Suspend Eastmark", flag: &s.SuspendEastmark,
			description: "The Union stops vouching for Eastmark's authority. Cross-border sign-ins with EastID fail; Eastmark's own services, which also trust their national authority directly, keep working."},
		{key: "compromise", title: "Eastmark's authority is compromised", flag: &s.CompromiseEastmark,
			description: "Eastmark's authority vouches for an impostor at bank.northland.localhost. The Union's naming constraints confine Eastmark to *.eastmark.localhost, so the impostor fails to resolve through the Union."},
	}
}

// activeScenes is the title of every scene that's on.
func (w *World) activeScenes() []string {
	var on []string
	for _, s := range w.sceneList() {
		if s.flag.Load() {
			on = append(on, s.title)
		}
	}
	return on
}

// tourStep is one step of the console's "Start here" walkthrough.
type tourStep struct {
	Title, Do, Notice string
	Links             []tourLink
	// Scene, when set, is the scene this step turns on.
	Scene *sceneRow
}

type tourLink struct{ Text, Href string }

// tour is the walkthrough: the README's "What to try", then each scene.
func (c *console) tour() []tourStep {
	bank := c.w.URL("bank.southport.localhost", "/")
	telco := c.w.URL("telco.eastmark.localhost", "/")
	resolve := func(host, via string) string {
		return "/resolve?via=" + via + "&subject=" + url.QueryEscape(c.w.entityID(host))
	}
	scenes := map[string]*sceneRow{}
	for _, row := range c.sceneRows() {
		scenes[row.Key] = &row
	}
	return []tourStep{
		{
			Title: "Sign in across a border",
			Do:    "Open Southport Savings Bank, choose EastID, and sign in as an Eastmark citizen.",
			Notice: "Neither the bank nor EastID was ever told about the other. Each resolved the other's Trust Chain up to the Union on first contact " +
				"— the requests appear under Recent federation traffic below.",
			Links: []tourLink{{"Open the bank", bank}},
		},
		{
			Title:  "Share only what you choose",
			Do:     "Sign in again, and untick Home address on EastID's consent page.",
			Notice: "Only what's ticked leaves EastID: the bank's page shows the address as not shared.",
			Links:  []tourLink{{"Open the bank", bank}},
		},
		{
			Title: "See the Union's rules applied",
			Do:    "Open the bank's Trust Chain.",
			Notice: "Compare the metadata the bank declares with the result after every superior's policy: the Union removes one of its three grant types, " +
				"and Southport requires services to publish a contact.",
			Links: []tourLink{{"Bank's trust chain", resolve("bank.southport.localhost", "union")}},
		},
		{
			Title:  "Check an assurance mark",
			Do:     "Open EastID's Trust Chain.",
			Notice: "Its level-of-assurance Trust Mark was issued by Eastmark's Accreditation Office — an issuer the Union lists as accredited — so services accept EastID.",
			Links:  []tourLink{{"EastID's trust chain", resolve(countryHost("id", "eastmark"), "union")}},
		},
		{
			Title:  "A provider forges its mark",
			Do:     "Turn the scene on, then open the bank and EastID's Trust Chain again.",
			Notice: "The bank refuses EastID: the forged mark's signature is valid, but EastID isn't accredited to issue it.",
			Links:  []tourLink{{"Open the bank", bank}, {"EastID's trust chain", resolve(countryHost("id", "eastmark"), "union")}},
			Scene:  scenes["forge"],
		},
		{
			Title:  "Suspend a country",
			Do:     "Turn off the forgery, turn this scene on, then sign in with EastID at the bank and at Eastmark Telecom.",
			Notice: "The bank can no longer reach EastID through the Union. Eastmark Telecom still can: it also trusts Eastmark's own authority directly.",
			Links:  []tourLink{{"Open the bank", bank}, {"Open the telecom", telco}},
			Scene:  scenes["suspend"],
		},
		{
			Title:  "Contain a compromised authority",
			Do:     "Turn the scene on, then resolve the impostor both ways.",
			Notice: "Eastmark's authority now vouches for a Northland host. Through the Union, naming constraints reject it; through Eastmark's authority alone, it resolves.",
			Links: []tourLink{
				{"Impostor, trusting the Union", resolve(impostorHost, "union")},
				{"Impostor, trusting Eastmark", resolve(impostorHost, "eastmark")},
			},
			Scene: scenes["compromise"],
		},
	}
}
