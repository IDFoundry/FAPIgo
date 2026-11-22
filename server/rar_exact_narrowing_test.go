package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
)

// limitDetail is a payment detail whose "limit" is a plain int: consent
// that reads it with extension.RARGet and grants it with RARSet stores
// "limit":0, the strictest limit there is, and encoding/json reads a
// "limit" left out, null or -0 as that same 0.
type limitDetail struct {
	Account string `json:"account"`
	Limit   int    `json:"limit"`
}

// limitRARDef sets neither ValidateNarrowing nor ValidateGrant, so the
// default exact match judges every narrowing of it.
var limitRARDef = extension.RARDefinition[limitDetail]{Type: "payment", MaxObjects: 3, MaxBytesPerObject: 512}

const (
	limitRequested = `[{"type":"payment","account":"acct-1","limit":0}]`
	// limitGranted is limitRequested as RARSet re-encodes it at consent.
	limitGranted = `[{"account":"acct-1","limit":0,"type":"payment"}]`
)

// rarRegistryOf registers def alone.
func rarRegistryOf[T any](t *testing.T, def extension.RARDefinition[T]) *extension.RARRegistry {
	t.Helper()
	registry, err := extension.NewRARRegistry(4096, 4, def)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return registry
}

// allowRequestedRARHarness is a harness for registry at assurance, whose
// client may use types under both grants, as
// AllowRequestedAuthorizationDetails lets it.
func allowRequestedRARHarness(t *testing.T, registry *extension.RARRegistry, assurance server.AssuranceLevel, types ...string) harness {
	t.Helper()
	allow := server.AllowRequestedAuthorizationDetails{}
	return newHarnessWithRARAt(t, server.ProfileFAPISecurity, registry, allow, allow, types, assurance)
}

// rarConsent turns the details an interaction asks for into the details
// the resource owner grants.
type rarConsent func(t *testing.T, requested extension.RARValues) []json.RawMessage

// consentAsRequested grants every requested object of def's type as the
// RAR guide shows: read with RARGet, granted re-encoded with RARSet.
func consentAsRequested[T any](def extension.RARDefinition[T]) rarConsent {
	return func(t *testing.T, requested extension.RARValues) []json.RawMessage {
		t.Helper()
		details, err := extension.RARGet(requested, def)
		if err != nil {
			t.Fatalf("RARGet: %v", err)
		}
		granted := make([]json.RawMessage, 0, len(details))
		for _, d := range details {
			raw, err := extension.RARSet(def, d.Fields)
			if err != nil {
				t.Fatalf("RARSet: %v", err)
			}
			granted = append(granted, raw)
		}
		return granted
	}
}

// consentGranting grants details, a JSON array a consent page writes
// itself.
func consentGranting(details string) rarConsent {
	return func(t *testing.T, _ extension.RARValues) []json.RawMessage {
		t.Helper()
		return rawDetails(t, details)
	}
}

// issueCodeConsenting pushes a request for requested, grants what consent
// returns for it, and returns the authorization code.
func issueCodeConsenting(t *testing.T, h harness, requested string, consent rarConsent) string {
	t.Helper()
	interaction := pushAndBeginAuthorization(t, h, requested)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts", "offline_access"},
			AuthorizationDetails: consent(t, interaction.Interaction.AuthorizationDetails),
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	dest := result.(server.AuthorizationRedirect).Destination().URL()
	return dest.Query().Get("code")
}

// approveBackchannelConsenting begins a CIBA request for requested,
// grants what consent returns for it, and returns the auth_req_id.
func approveBackchannelConsenting(t *testing.T, h harness, requested string, consent rarConsent) string {
	t.Helper()
	params := standardBackchannelParams(t)
	params["authorization_details"] = json.RawMessage(requested)
	required := beginBackchannel(t, h, params)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts"},
			AuthorizationDetails: consent(t, required.Interaction.AuthorizationDetails),
		}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	return required.AuthReqID.String()
}

// narrowingGrants are the token requests that may narrow a grant's
// authorization_details. Each narrow makes a grant of requested, which
// consent approves, and asks for narrowed from it (nil: no
// authorization_details parameter).
var narrowingGrants = []struct {
	name   string
	narrow func(t *testing.T, h harness, requested string, consent rarConsent, narrowed *string) (server.TokenResult, error)
}{
	{"code exchange", narrowAtCodeExchange},
	{"refresh", narrowAtRefresh},
	{"CIBA token exchange", narrowAtBackchannelExchange},
}

func narrowAtCodeExchange(t *testing.T, h harness, requested string, consent rarConsent, narrowed *string) (server.TokenResult, error) {
	t.Helper()
	return rarExchangeCode(t, h, issueCodeConsenting(t, h, requested, consent), narrowed)
}

func narrowAtRefresh(t *testing.T, h harness, requested string, consent rarConsent, narrowed *string) (server.TokenResult, error) {
	t.Helper()
	first, err := rarExchangeCode(t, h, issueCodeConsenting(t, h, requested, consent), nil)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !first.HasRefreshToken {
		t.Fatal("no refresh token issued")
	}
	return rarRefresh(t, h, first.RefreshToken.Reveal(), narrowed)
}

func narrowAtBackchannelExchange(t *testing.T, h harness, requested string, consent rarConsent, narrowed *string) (server.TokenResult, error) {
	t.Helper()
	return rarExchangeBackchannel(t, h, approveBackchannelConsenting(t, h, requested, consent), narrowed)
}

// assertNarrowingIssues narrows a grant of requested, which consent
// approves, to each of narrowed at every grant, and checks that the
// token carries want.
func assertNarrowingIssues(t *testing.T, h harness, requested string, consent rarConsent, narrowed []*string, want string) {
	t.Helper()
	for _, grant := range narrowingGrants {
		for _, details := range narrowed {
			result, err := grant.narrow(t, h, requested, consent, details)
			if err != nil {
				t.Fatalf("%s narrowing to %s: %v", grant.name, rawOrAbsent(details), err)
			}
			assertIssuedJSON(t, h, result, want)
		}
	}
}

// assertNarrowingRefused is assertNarrowingIssues for a narrowed every
// grant must refuse with invalid_authorization_details.
func assertNarrowingRefused(t *testing.T, h harness, requested string, consent rarConsent, narrowed string) {
	t.Helper()
	for _, grant := range narrowingGrants {
		_, err := grant.narrow(t, h, requested, consent, &narrowed)
		assertInvalidAuthorizationDetails(t, err)
	}
}

func rawOrAbsent(details *string) string {
	if details == nil {
		return "no authorization_details"
	}
	return *details
}

var rarAssuranceLevels = []struct {
	name  string
	level server.AssuranceLevel
}{
	{"development", server.AssuranceDevelopment},
	{"production", server.AssuranceProduction},
}

// TestTokenRequestNarrowingIssuesTheGrantedObject: with neither
// ValidateNarrowing nor ValidateGrant, a token request's
// authorization_details is matched against the grant decoded into the
// type's Go value, where a "limit" left out, null or -0 reads as the 0
// the grant holds. At every grant a token request may narrow, and at both
// assurance levels, the access token and the token response carry the
// granted object as stored (RFC 9396 §7), not the client's spelling of
// it, which a resource server reading the claim as plain JSON, or into a
// pointer, would read as no limit at all.
func TestTokenRequestNarrowingIssuesTheGrantedObject(t *testing.T) {
	narrowed := []*string{
		nil, // the whole grant, as stored
		rarParam(limitGranted),
		rarParam(limitRequested),
		rarParam(`[{"type":"payment","account":"acct-1"}]`),
		rarParam(`[{"type":"payment","account":"acct-1","limit":null}]`),
		rarParam(`[{"type":"payment","account":"acct-1","limit":-0}]`),
		rarParam(`[ {"limit":0, "type":"payment", "account":"acct-1"} ]`),
	}
	consent := consentAsRequested(limitRARDef)
	for _, a := range rarAssuranceLevels {
		t.Run(a.name, func(t *testing.T) {
			h := allowRequestedRARHarness(t, rarRegistryOf(t, limitRARDef), a.level, "payment")
			assertNarrowingIssues(t, h, limitRequested, consent, narrowed, limitGranted)
			// What the exact match tells apart is still refused.
			assertNarrowingRefused(t, h, limitRequested, consent, `[{"type":"payment","account":"acct-1","limit":1}]`)
			assertNarrowingRefused(t, h, limitRequested, consent, `[{"type":"payment","account":"acct-2","limit":0}]`)
		})
	}
}

// floatAccountDetail holds its account number as a float64, which
// encoding/json rounds to the nearest float64 it can hold.
type floatAccountDetail struct {
	Account float64 `json:"account"`
}

// TestTokenRequestNarrowingIssuesTheGrantedNumber: numbers that round to
// the granted float64 are matched to the grant, whether the type holds
// them in a float64 or in a map[string]any, and the token carries the
// granted number, not the client's.
func TestTokenRequestNarrowingIssuesTheGrantedNumber(t *testing.T) {
	const (
		requested = `[{"type":"payment","account":12345678901234567}]`
		granted   = `[{"account":12345678901234568,"type":"payment"}]`
	)
	narrowed := []*string{
		nil,
		rarParam(requested),
		rarParam(`[{"type":"payment","account":12345678901234569}]`),
		rarParam(`[{"type":"payment","account":1.2345678901234568e16}]`),
	}
	floatDef := extension.RARDefinition[floatAccountDetail]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 512}
	mapDef := extension.RARDefinition[map[string]any]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 512}
	for _, tc := range []struct {
		name     string
		registry *extension.RARRegistry
		consent  rarConsent
	}{
		{"float64", rarRegistryOf(t, floatDef), consentAsRequested(floatDef)},
		{"map[string]any", rarRegistryOf(t, mapDef), consentAsRequested(mapDef)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := allowRequestedRARHarness(t, tc.registry, server.AssuranceDevelopment, "payment")
			assertNarrowingIssues(t, h, requested, tc.consent, narrowed, granted)
			assertNarrowingRefused(t, h, requested, tc.consent, `[{"type":"payment","account":12345678901234570}]`)
		})
	}
}

// actionsDetail's "actions" is omitempty: encoding/json reads it left out
// as the empty list a consent page may grant explicitly, no action at
// all, where a resource server may read a missing list as no restriction.
type actionsDetail struct {
	Account string   `json:"account"`
	Actions []string `json:"actions,omitempty"`
}

// TestRefreshNarrowingKeepsAnEmptyGrantedList: a refresh asking for the
// granted object without its empty "actions" list is matched to it, and
// the access token carries the list as granted.
func TestRefreshNarrowingKeepsAnEmptyGrantedList(t *testing.T) {
	const (
		requested = `[{"type":"payment","account":"acct-1","actions":[]}]`
		dropped   = `[{"type":"payment","account":"acct-1"}]`
	)
	def := extension.RARDefinition[actionsDetail]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 512}
	h := allowRequestedRARHarness(t, rarRegistryOf(t, def), server.AssuranceDevelopment, "payment")
	result, err := narrowAtRefresh(t, h, requested, consentGranting(requested), rarParam(dropped))
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	assertIssuedJSON(t, h, result, requested)

	// A list that isn't empty can't be left out at all.
	const granted = `[{"type":"payment","account":"acct-1","actions":["read"]}]`
	_, err = narrowAtRefresh(t, h, granted, consentGranting(granted), rarParam(dropped))
	assertInvalidAuthorizationDetails(t, err)
}

// lowerLimit is a ValidateNarrowing hook letting a token request lower a
// granted limit on the same account.
func lowerLimit(granted, narrowed limitDetail) error {
	if narrowed.Account != granted.Account || narrowed.Limit > granted.Limit {
		return errors.New("not a lower limit on the granted account")
	}
	return nil
}

// cappedRARDef is limitRARDef's shape under a ValidateNarrowing hook. The
// hook judges the object the client sends, which the token then carries
// as sent.
var cappedRARDef = extension.RARDefinition[limitDetail]{
	Type: "capped", MaxObjects: 3, MaxBytesPerObject: 512, ValidateNarrowing: lowerLimit,
}

// TestTokenRequestNarrowingKeepsTheRequestsOrder: a token request naming
// objects of a type the exact match judges and of one a hook judges gets
// them back in its own order, the exact match's as granted and the
// hook's as sent.
func TestTokenRequestNarrowingKeepsTheRequestsOrder(t *testing.T) {
	const (
		requested = `[{"type":"payment","account":"acct-1","limit":0},{"type":"capped","account":"acct-9","limit":50},{"type":"payment","account":"acct-2","limit":0}]`
		narrowed  = `[{"type":"capped","account":"acct-9","limit":20},{"type":"payment","account":"acct-2"},{"type":"payment","account":"acct-1","limit":null}]`
		want      = `[{"type":"capped","account":"acct-9","limit":20},{"type":"payment","account":"acct-2","limit":0},{"type":"payment","account":"acct-1","limit":0}]`
	)
	for _, a := range rarAssuranceLevels {
		t.Run(a.name, func(t *testing.T) {
			registry, err := extension.NewRARRegistry(4096, 4, limitRARDef, cappedRARDef)
			if err != nil {
				t.Fatalf("NewRARRegistry: %v", err)
			}
			h := allowRequestedRARHarness(t, registry, a.level, "payment", "capped")
			assertNarrowingIssues(t, h, requested, consentGranting(requested), []*string{rarParam(narrowed)}, want)
		})
	}
}

// TestTokenRequestNarrowingIssuesWhatAHookJudged: under a
// ValidateNarrowing hook, the token carries the object the client sent
// and the hook accepted, compacted but otherwise as sent; the hook still
// refuses what it doesn't accept.
func TestTokenRequestNarrowingIssuesWhatAHookJudged(t *testing.T) {
	const (
		requested = `[{"type":"capped","account":"acct-9","limit":50}]`
		lowered   = `[{"limit":20, "type":"capped", "account":"acct-9"}]`
	)
	h := allowRequestedRARHarness(t, rarRegistryOf(t, cappedRARDef), server.AssuranceDevelopment, "capped")
	assertNarrowingIssues(t, h, requested, consentGranting(requested), []*string{rarParam(lowered)}, lowered)
	assertNarrowingRefused(t, h, requested, consentGranting(requested), `[{"type":"capped","account":"acct-9","limit":51}]`)
}
