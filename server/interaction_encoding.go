package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
)

// interactionRequestVersion prefixes every encoded InteractionRequest,
// so a later format can be told apart.
const interactionRequestVersion = "v1."

// maxEncodedInteractionRequest bounds what ParseInteractionRequest reads.
const maxEncodedInteractionRequest = 64 << 10

// encodedInteractionRequest is the JSON inside an encoded
// InteractionRequest.
type encodedInteractionRequest struct {
	ClientID             fapi.ClientID       `json:"client_id"`
	Scope                []string            `json:"scope,omitempty"`
	LoginHint            LoginHint           `json:"login_hint,omitempty"`
	ACRValues            []string            `json:"acr_values,omitempty"`
	EssentialACRValues   []string            `json:"essential_acr_values,omitempty"`
	RequiredSubject      string              `json:"required_subject,omitempty"`
	MaxAgeSeconds        *int64              `json:"max_age,omitempty"`
	Prompt               Prompt              `json:"prompt,omitempty"`
	ClientName           string              `json:"client_name,omitempty"`
	LogoURI              string              `json:"logo_uri,omitempty"`
	PolicyURI            string              `json:"policy_uri,omitempty"`
	TermsOfServiceURI    string              `json:"tos_uri,omitempty"`
	AuthorizationDetails extension.RARValues `json:"authorization_details"`
	IDTokenClaims        []string            `json:"id_token_claims,omitempty"`
	UserInfoClaims       []string            `json:"userinfo_claims,omitempty"`
	Extensions           extension.Values    `json:"extensions"`
}

// MarshalText encodes r for storage, so the interaction can be shown and
// completed on an instance other than the one that began it: keep the
// encoding with the InteractionHandle (its String form) in the
// application's own shared session store, and restore it with
// ParseInteractionRequest (or UnmarshalText).
//
// The encoding is opaque and versioned. It can carry personal data (the
// login hint, authorization details), so store it as you would the rest
// of a session. It carries no integrity protection and needs none for
// the grant's sake: CompleteAuthorization checks the granted scope,
// authorization details and identity claims against the request the
// server stored itself, so a modified copy can make a consent screen
// show less than was asked, and the grant built from it smaller, but
// never larger. Store it where only the application can write it all the
// same, so what the end user sees is what was asked.
func (r InteractionRequest) MarshalText() ([]byte, error) {
	if r.ClientID == "" {
		return nil, errors.New("server: an interaction request without a client can't be encoded")
	}
	var maxAge *int64
	if r.HasMaxAge {
		seconds := int64(r.MaxAge / time.Second)
		maxAge = &seconds
	}
	raw, err := json.Marshal(encodedInteractionRequest{
		ClientID: r.ClientID, Scope: r.Scope, LoginHint: r.Hints.LoginHint,
		ACRValues: r.ACRValues, EssentialACRValues: r.EssentialACRValues, RequiredSubject: r.RequiredSubject, MaxAgeSeconds: maxAge, Prompt: r.Prompt,
		ClientName: r.ClientDisplay.Name, LogoURI: urlString(r.ClientDisplay.LogoURI),
		PolicyURI: urlString(r.ClientDisplay.PolicyURI), TermsOfServiceURI: urlString(r.ClientDisplay.TermsOfServiceURI),
		AuthorizationDetails: r.AuthorizationDetails,
		IDTokenClaims:        r.RequestedClaims.IDToken, UserInfoClaims: r.RequestedClaims.UserInfo,
		Extensions: r.Extensions,
	})
	if err != nil {
		return nil, err
	}
	return []byte(interactionRequestVersion + base64.RawURLEncoding.EncodeToString(raw)), nil
}

// UnmarshalText restores an InteractionRequest MarshalText encoded — see
// ParseInteractionRequest.
func (r *InteractionRequest) UnmarshalText(text []byte) error {
	parsed, err := ParseInteractionRequest(string(text))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// ParseInteractionRequest restores an InteractionRequest
// InteractionRequest.MarshalText encoded. A value that isn't such an
// encoding is an error.
func ParseInteractionRequest(text string) (InteractionRequest, error) {
	invalid := func(cause error) (InteractionRequest, error) {
		return InteractionRequest{}, errors.Join(errors.New("server: not an encoded interaction request"), cause)
	}
	if len(text) > maxEncodedInteractionRequest {
		return invalid(errors.New("too long"))
	}
	payload, ok := strings.CutPrefix(text, interactionRequestVersion)
	if !ok {
		return invalid(errors.New("unknown version"))
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return invalid(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e encodedInteractionRequest
	if err := dec.Decode(&e); err != nil {
		return invalid(err)
	}
	if e.ClientID == "" {
		return invalid(errors.New("no client_id"))
	}
	display := storage.ClientDisplay{Name: e.ClientName}
	for _, u := range []struct {
		raw string
		dst *fapi.URL
	}{{e.LogoURI, &display.LogoURI}, {e.PolicyURI, &display.PolicyURI}, {e.TermsOfServiceURI, &display.TermsOfServiceURI}} {
		if u.raw == "" {
			continue
		}
		if *u.dst, err = fapi.ParseEndpointURL(u.raw); err != nil {
			return invalid(err)
		}
	}
	r := InteractionRequest{
		ClientID: e.ClientID, Scope: e.Scope, Hints: AuthenticationHints{LoginHint: e.LoginHint},
		ACRValues:          e.ACRValues,
		EssentialACRValues: e.EssentialACRValues,
		RequiredSubject:    e.RequiredSubject,
		Prompt:             e.Prompt,
		ClientDisplay:      display, AuthorizationDetails: e.AuthorizationDetails,
		RequestedClaims: RequestedClaims{IDToken: e.IDTokenClaims, UserInfo: e.UserInfoClaims},
		Extensions:      e.Extensions,
	}
	if e.MaxAgeSeconds != nil {
		if *e.MaxAgeSeconds < 0 || *e.MaxAgeSeconds > maxMaxAge {
			return invalid(errors.New("max_age is out of range"))
		}
		r.MaxAge, r.HasMaxAge = time.Duration(*e.MaxAgeSeconds)*time.Second, true
	}
	return r, nil
}

func urlString(u fapi.URL) string {
	if u.IsZero() {
		return ""
	}
	return u.String()
}
