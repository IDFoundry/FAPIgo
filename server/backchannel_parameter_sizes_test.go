package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// countingSubjects is hintSubjects, counting the hints it resolves.
type countingSubjects struct {
	hintSubjects
	calls int
}

func (r *countingSubjects) ResolveBackchannelSubject(ctx context.Context, clientID fapi.ClientID, hints server.BackchannelAuthenticationHints) (server.SubjectID, error) {
	r.calls++
	return r.hintSubjects.ResolveBackchannelSubject(ctx, clientID, hints)
}

// countingInbox is a memstore BackchannelInbox counting the requests
// filed in it.
type countingInbox struct {
	*memstore.BackchannelInbox
	filed int
}

func (b *countingInbox) AddBackchannelRequest(ctx context.Context, entry storage.NewBackchannelInboxEntry) error {
	b.filed++
	return b.BackchannelInbox.AddBackchannelRequest(ctx, entry)
}

// backchannelBeginCalls are what BeginBackchannelAuthentication asks
// once a request is valid — the hint checker, the subject resolver, the
// inbox and the backchannel store — each counting its calls.
type backchannelBeginCalls struct {
	hints    *hintChecker
	subjects *countingSubjects
	inbox    *countingInbox
	store    *countingBackchannelStore
}

func (c backchannelBeginCalls) counts() [4]int {
	return [4]int{c.hints.calls, c.subjects.calls, c.inbox.filed, c.store.created}
}

// newBackchannelBeginCallsHarness is a CIBA harness for user-1 whose
// hint checker, subject resolver, inbox and backchannel store count
// what they're asked.
func newBackchannelBeginCallsHarness(t *testing.T) (harness, backchannelBeginCalls) {
	t.Helper()
	calls := backchannelBeginCalls{
		hints:    &hintChecker{known: "user-1", err: server.ErrUnknownUserID},
		subjects: &countingSubjects{hintSubjects: hintSubjects{known: map[string]bool{"user-1": true}}},
		inbox:    &countingInbox{BackchannelInbox: memstore.NewBackchannelInbox()},
		store:    &countingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()},
	}
	h := newHarnessWithBackchannelOptions(t, calls.store, nil, func(d *server.Dependencies) {
		d.BackchannelHints = calls.hints
		d.BackchannelSubjects = calls.subjects
		d.BackchannelInbox = calls.inbox
	})
	return h, calls
}

// beginBackchannelWith is BeginBackchannelAuthentication for
// standardBackchannelParams with name set to value.
func beginBackchannelWith(t *testing.T, h harness, name string, value json.RawMessage) server.BackchannelAuthenticationAction {
	t.Helper()
	params := standardBackchannelParams(t)
	params[name] = value
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return action
}

// acrValues is n distinct acr values, space-separated.
func acrValues(n int) string {
	values := make([]string, n)
	for i := range values {
		values[i] = fmt.Sprintf("urn:acr:%d", i)
	}
	return strings.Join(values, " ")
}

// TestBeginBackchannelAuthenticationBoundsCoreParameterSizes: a
// backchannel authentication request's core parameters have the bounds
// a pushed request's have, and its acr_values names at most 32 values,
// since every lookup of the request and listing of its user's inbox
// splits them again. One over its bound is refused with invalid_request
// before the hint is checked or resolved, and before anything is filed
// or stored. A request within the bounds reaches each of them once.
func TestBeginBackchannelAuthenticationBoundsCoreParameterSizes(t *testing.T) {
	t.Run("within the bounds", func(t *testing.T) {
		h, calls := newBackchannelBeginCallsHarness(t)
		action := beginBackchannelWith(t, h, "acr_values", jsonRaw(t, acrValues(32)))
		if _, ok := action.(server.BackchannelInteractionRequired); !ok {
			t.Fatalf("action = %#v, want BackchannelInteractionRequired", action)
		}
		if got := calls.counts(); got != [4]int{1, 1, 1, 1} {
			t.Fatalf("hint checks, subject resolutions, filings, stored requests = %v, want one each", got)
		}
	})
	for name, value := range map[string]json.RawMessage{
		"login_hint":           jsonRaw(t, strings.Repeat("h", 4<<10+1)),
		"acr_values":           jsonRaw(t, strings.Repeat("a", 4<<10+1)),
		"acr_values count":     jsonRaw(t, acrValues(33)),
		"acr_values one-byte":  jsonRaw(t, strings.Repeat("a ", 2<<10)),
		"acr_values separated": jsonRaw(t, strings.Repeat("a\t\n　", 33)),
		"scope":                jsonRaw(t, repeatedScope("openid", 4<<10)),
		"dpop_jkt":             jsonRaw(t, strings.Repeat("j", 129)),
		"requested_expiry":     jsonRaw(t, strings.Repeat("0", 32)+"1"),
	} {
		t.Run(name, func(t *testing.T) {
			h, calls := newBackchannelBeginCallsHarness(t)
			action := beginBackchannelWith(t, h, parameterOf(name), value)
			local, ok := action.(server.BackchannelAuthenticationLocalError)
			if !ok || local.Error.Code() != server.ErrorInvalidRequest {
				t.Fatalf("action = %#v, want an invalid_request local error", action)
			}
			if !strings.Contains(local.Error.PublicDescription(), parameterOf(name)+" must not") {
				t.Fatalf("description = %q, want the bound of %s named", local.Error.PublicDescription(), parameterOf(name))
			}
			if got := calls.counts(); got != [4]int{} {
				t.Fatalf("hint checks, subject resolutions, filings, stored requests = %v, want none", got)
			}
		})
	}
}

// TestBeginBackchannelAuthenticationAcceptsCoreParametersAtTheirBound:
// a value exactly at its bound is still accepted, and every one of 32
// acr values reaches the interaction.
func TestBeginBackchannelAuthenticationAcceptsCoreParametersAtTheirBound(t *testing.T) {
	for name, value := range map[string]json.RawMessage{
		"login_hint":       jsonRaw(t, strings.Repeat("h", 4<<10)),
		"acr_values":       jsonRaw(t, strings.Repeat("a", 4<<10)),
		"acr_values count": jsonRaw(t, acrValues(32)),
		"dpop_jkt":         jsonRaw(t, strings.Repeat("j", 128)),
		"requested_expiry": jsonRaw(t, strings.Repeat("0", 31)+"1"),
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			action := beginBackchannelWith(t, h, parameterOf(name), value)
			required, ok := action.(server.BackchannelInteractionRequired)
			if !ok {
				t.Fatalf("action = %#v, want BackchannelInteractionRequired", action)
			}
			if name == "acr_values count" && len(required.Interaction.ACRValues) != 32 {
				t.Fatalf("Interaction.ACRValues has %d values, want 32", len(required.Interaction.ACRValues))
			}
		})
	}
}
