package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
)

// unavailableLookup is a Reversible deriver whose lookup answers New's
// probe and then can't be answered (an unreachable store, say): an error
// that isn't pairwise.ErrSubjectNotFound.
type unavailableLookup struct{ *mappingDeriver }

func (u unavailableLookup) LookupInternalSubject(ctx context.Context, issuer, sector, body string) (string, error) {
	if subject, err := u.mappingDeriver.LookupInternalSubject(ctx, issuer, sector, body); err == nil && subject == "fapigo-pairwise-probe" {
		return subject, nil
	}
	return "", errors.New("lookup store unavailable")
}

// TestClientSubjectFailsClosed: ClientSubject reports a derivation it
// can't complete as server_error, never the internal subject.
func TestClientSubjectFailsClosed(t *testing.T) {
	h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.OneWay, failingDeriver{hmacDeriver(t)})
	sub, err := h.server.ClientSubject(context.Background(), testClientID, mustAuthenticated(t, "user-1"))
	if code := serverErrorCode(t, err); code != server.ErrorServerError || sub != "" {
		t.Fatalf("ClientSubject = %q, %v; want no sub and server_error", sub, err)
	}
}

// TestPairwiseRequiredSubjectLookupUnavailable: when a sub value can't be
// mapped back because the lookup can't answer, the request fails with
// server_error, at PAR and at the backchannel endpoint, rather than
// being read as naming no one (invalid_request) or as naming no
// requirement at all.
func TestPairwiseRequiredSubjectLookupUnavailable(t *testing.T) {
	sub := testPairwisePrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	t.Run("PAR", func(t *testing.T) {
		h := withPairwise(t, newHarness(t, server.ProfileFAPISecurity, true), pairwiseClient(false), pairwise.Reversible, unavailableLookup{newMappingDeriver()})
		err := pushPAR(t, h, map[string]string{"claims": subClaims("id_token", sub)})
		if code := serverErrorCode(t, err); code != server.ErrorServerError {
			t.Fatalf("PushAuthorizationRequest error code = %q, want server_error", code)
		}
	})
	t.Run("CIBA", func(t *testing.T) {
		h := cibaWithPairwise(t, pairwise.Reversible, unavailableLookup{newMappingDeriver()})
		params := standardBackchannelParams(t)
		params["claims"] = json.RawMessage(subClaims("id_token", sub))
		assertBackchannelLocalError(t, h, params, server.ErrorServerError)
	})
}

// TestPairwiseRequiredSubjectPublicClientUnderPairwiseOnly: a sub value
// from a client registered public, at a server that issues only pairwise
// subjects, fails with server_error: the client can't be given any sub.
func TestPairwiseRequiredSubjectPublicClientUnderPairwiseOnly(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	public := pairwiseClient(false)
	public.SubjectType = fapi.SubjectTypePublic
	register(t, h, public)
	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPairwiseOnly,
		Derivation: pairwise.Reversible, Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = newMappingDeriver()
	srv, err := server.NewIssuingPairwiseSubjects(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("NewIssuingPairwiseSubjects: %v", err)
	}
	h.server = srv
	err = pushPAR(t, h, map[string]string{"claims": subClaims("id_token", "user-1")})
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("PushAuthorizationRequest error code = %q, want server_error", code)
	}
}

// TestBackchannelCompletionFailsClosedWithoutClientSubject: a CIBA
// approval whose client sub can't be worked out (the client is gone, or
// is pairwise by default with no sector to derive under) is refused with
// server_error, and the poll gets no tokens.
func TestBackchannelCompletionFailsClosedWithoutClientSubject(t *testing.T) {
	t.Run("client no longer registered", func(t *testing.T) {
		h := cibaWithPairwise(t, pairwise.OneWay, hmacDeriver(t))
		required := beginBackchannel(t, h, standardBackchannelParams(t))
		delete(h.clients.clients, testClientID)
		assertBackchannelCompletionServerError(t, h, required)
	})
	t.Run("pairwise by default, no sector", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		noSector := pairwiseClient(true)
		noSector.SubjectType = 0 // the server's default: pairwise
		noSector.RedirectURIs = nil
		register(t, h, noSector)
		h.cfg.Subjects = server.SubjectConfig{
			Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPerClient,
			Derivation: pairwise.OneWay, Prefix: mustPrefix(t, testPairwisePrefix),
		}
		h.deps.PairwiseSubjects = hmacDeriver(t)
		srv, err := server.NewIssuingPairwiseSubjects(h.cfg, h.deps)
		if err != nil {
			t.Fatalf("NewIssuingPairwiseSubjects: %v", err)
		}
		h.server = srv
		required := beginBackchannel(t, h, standardBackchannelParams(t))
		assertBackchannelCompletionServerError(t, h, required)
	})
}

// assertBackchannelLocalError begins a backchannel authentication with
// params and checks it fails locally with code.
func assertBackchannelLocalError(t *testing.T, h harness, params map[string]json.RawMessage, code server.ErrorCode) {
	t.Helper()
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if local, ok := action.(server.BackchannelAuthenticationLocalError); !ok || local.Error.Code() != code {
		t.Fatalf("action = %#v, want a %s local error", action, code)
	}
}

// assertBackchannelCompletionServerError approves required as user-1
// and checks the completion fails with server_error.
func assertBackchannelCompletionServerError(t *testing.T, h harness, required server.BackchannelInteractionRequired) {
	t.Helper()
	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizedAs(t, h, "user-1"),
	})
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("CompleteBackchannelAuthentication error code = %q, want server_error", code)
	}
}
