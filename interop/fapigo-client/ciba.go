package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/idfoundry/fapigo/client"
)

const (
	// cibaBindingMessage is shown on both devices (CIBA Core §7.1).
	cibaBindingMessage = "fapigo-interop"

	// maxCIBAPolls bounds polling after approval.
	maxCIBAPolls = 5

	// pingTimeout bounds the wait for the server's ping after approval.
	pingTimeout = 20 * time.Second
)

// cibaPoll is leg 5: a signed CIBA request, private_key_jwt,
// certificate-bound tokens; polling meets authorization_pending before
// the approval hook approves the request.
func cibaPoll(ctx context.Context, r run) error {
	cl, session, err := beginCIBA(ctx, r, false)
	if err != nil {
		return err
	}
	result, err := cl.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		return fmt.Errorf("poll before approval: %w", err)
	}
	pending, ok := result.(client.BackchannelAuthenticationPending)
	if !ok {
		return fmt.Errorf("poll before approval returned %T, want authorization_pending", result)
	}
	session = pending.Session
	if err := approveCIBA(r, session); err != nil {
		return err
	}
	return redeemCIBA(ctx, r, cl, session)
}

// cibaPing is leg 6: as leg 5 in ping mode. The driver serves the
// client_notification_endpoint; after approval it checks the ping's
// bearer token against the session and then redeems the auth_req_id.
func cibaPing(ctx context.Context, r run) error {
	cl, session, err := beginCIBA(ctx, r, true)
	if err != nil {
		return err
	}
	if session.NotificationToken() == "" {
		return errors.New("ping session has no client_notification_token")
	}
	if err := approveCIBA(r, session); err != nil {
		return err
	}
	select {
	case n := <-r.notifications:
		if n.AuthReqID() != session.AuthReqID() {
			return fmt.Errorf("ping for auth_req_id %q, want %q", n.AuthReqID(), session.AuthReqID())
		}
		if !n.Authenticates(session) {
			return errors.New("ping's bearer token is not the session's client_notification_token")
		}
	case <-time.After(pingTimeout):
		return fmt.Errorf("no ping within %s of approval", pingTimeout)
	case <-ctx.Done():
		return ctx.Err()
	}
	return redeemCIBA(ctx, r, cl, session)
}

func beginCIBA(ctx context.Context, r run, ping bool) (*client.Client, client.BackchannelAuthenticationSession, error) {
	cl, err := newClient(ctx, r.cfg, r.leg, clientShape{profile: client.ProfileFAPISecurity, senderMTLS: true, ciba: true, cibaPing: ping})
	if err != nil {
		return nil, client.BackchannelAuthenticationSession{}, err
	}
	session, err := cl.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope:          r.leg.Scope,
		LoginHint:      r.cfg.CIBALoginHint,
		BindingMessage: cibaBindingMessage,
	})
	if err != nil {
		return nil, client.BackchannelAuthenticationSession{}, fmt.Errorf("begin backchannel authentication: %w", err)
	}
	return cl, session, nil
}

// approveCIBA approves the request through the server's test hook, in
// place of the user's authentication device.
func approveCIBA(r run, session client.BackchannelAuthenticationSession) error {
	agent, err := newUserAgent(r.cfg)
	if err != nil {
		return err
	}
	if err := agent.post(r.cfg.CIBAApprovalURL, url.Values{"auth_req_id": {session.AuthReqID()}}); err != nil {
		return fmt.Errorf("approve: %w", err)
	}
	return nil
}

// redeemCIBA polls, at the session's interval, until the approved
// request's tokens are issued, then checks them and calls UserInfo.
func redeemCIBA(ctx context.Context, r run, cl *client.Client, session client.BackchannelAuthenticationSession) error {
	for range maxCIBAPolls {
		select {
		case <-time.After(session.Interval()):
		case <-ctx.Done():
			return ctx.Err()
		}
		result, err := cl.PollBackchannelAuthentication(ctx, session)
		if err != nil {
			return fmt.Errorf("poll: %w", err)
		}
		switch res := result.(type) {
		case client.BackchannelAuthenticationPending:
			session = res.Session
		case client.BackchannelAuthenticationApproved:
			if err := checkTokens(r, res.Tokens, "Bearer"); err != nil {
				return err
			}
			return checkUserInfo(ctx, r, cl, res.Tokens)
		default:
			return fmt.Errorf("approved request polled as %T", result)
		}
	}
	return fmt.Errorf("still pending after %d polls", maxCIBAPolls)
}

// notificationHandler is the CIBA ping leg's
// client_notification_endpoint: it parses each ping and hands it to the
// leg, which authenticates it against its session.
func notificationHandler(notifications chan<- client.BackchannelNotification) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n, err := client.ParseBackchannelNotification(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case notifications <- n:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
