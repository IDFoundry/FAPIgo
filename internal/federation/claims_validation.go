package federation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// explicitRegistrationClaims are the claims OpenID Federation 1.0 §3.2
// allows only in Explicit Registration requests or responses (steps 26
// and 27: aud and trust_anchor "MUST NOT be present in Entity Statements
// that are not Explicit Registration requests or responses"). This
// package implements no Explicit Registration, so every statement it
// parses is one they may not appear in.
var explicitRegistrationClaims = []string{"aud", "trust_anchor"}

// forbiddenStatementHeaders are the JWS header parameters an Entity
// Statement may not carry: §4.3 "Entity Configurations and Subordinate
// Statements MUST NOT contain the trust_chain header parameter", and
// §4.4 likewise for peer_trust_chain.
var forbiddenStatementHeaders = []string{"trust_chain", "peer_trust_chain"}

// refuseExplicitRegistrationClaims refuses a statement carrying aud or
// trust_anchor (§3.2 steps 26 and 27).
func refuseExplicitRegistrationClaims(raw map[string]json.RawMessage) error {
	for _, claim := range explicitRegistrationClaims {
		if _, ok := raw[claim]; ok {
			return fmt.Errorf("%w: %q may appear only in an Explicit Registration request or response (OpenID Federation 1.0 §3.2)", ErrMalformedClaims, claim)
		}
	}
	return nil
}

// refuseForbiddenHeaders refuses a statement whose JWS protected header
// (token's first segment, already decoded once by jose.ParseCompact)
// carries trust_chain or peer_trust_chain (§4.3, §4.4).
func refuseForbiddenHeaders(token string) error {
	headerB64, _, _ := strings.Cut(token, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("%w: header: %v", ErrForbiddenHeader, err)
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("%w: header: %v", ErrForbiddenHeader, err)
	}
	for _, name := range forbiddenStatementHeaders {
		if _, ok := header[name]; ok {
			return fmt.Errorf("%w: %q (OpenID Federation 1.0 §4.3, §4.4)", ErrForbiddenHeader, name)
		}
	}
	return nil
}

// parseMetadataClaim parses a "metadata" claim: a JSON object whose
// every member is an Entity Type's metadata, itself a JSON object (§5:
// "The metadata data structure following each Entity Type Identifier is
// a JSON object") whose top-level members are never null (§5: "MAY use
// any JSON value other than null"; §3.2 step 16 "not using null as
// metadata values").
func parseMetadataClaim(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(raw, &metadata); err != nil || metadata == nil {
		return nil, fmt.Errorf("%w: metadata must be a JSON object", ErrMalformedClaims)
	}
	for entityType, value := range metadata {
		var params map[string]json.RawMessage
		if err := json.Unmarshal(value, &params); err != nil || params == nil {
			return nil, fmt.Errorf("%w: metadata.%s must be a JSON object (OpenID Federation 1.0 §5)", ErrMalformedClaims, entityType)
		}
		for name, param := range params {
			if isJSONNull(param) {
				return nil, fmt.Errorf("%w: metadata.%s.%s is null (OpenID Federation 1.0 §5)", ErrMalformedClaims, entityType, name)
			}
		}
	}
	return metadata, nil
}

// parseNonEmptyStrings parses claim's value as a non-empty array of
// non-empty strings: authority_hints, trust_anchor_hints (§3.1.2 "MUST
// NOT be the empty array") and metadata_policy_crit (§3.1.3 likewise).
func parseNonEmptyStrings(raw json.RawMessage, claim string) ([]string, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedClaims, claim, err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: %s must not be the empty array (OpenID Federation 1.0 §3.1)", ErrMalformedClaims, claim)
	}
	for i, v := range values {
		if v == "" {
			return nil, fmt.Errorf("%w: %s[%d] is empty", ErrMalformedClaims, claim, i)
		}
	}
	return values, nil
}

// parseEntityIdentifiers is parseNonEmptyStrings for a claim listing
// Entity Identifiers (authority_hints, trust_anchor_hints), each of
// which must also be an https URL (§1.2).
func parseEntityIdentifiers(raw json.RawMessage, claim string) ([]string, error) {
	ids, err := parseNonEmptyStrings(raw, claim)
	if err != nil {
		return nil, err
	}
	for i, id := range ids {
		if !isHTTPSURL(id) {
			return nil, fmt.Errorf("%w: %s[%d] is not an https Entity Identifier", ErrMalformedClaims, claim, i)
		}
	}
	return ids, nil
}

// parseSourceEndpoint parses a "source_endpoint" claim, which §3.2 step
// 23 says to "Validate that its Claim Value is a URL": an absolute
// https URL, like every federation endpoint.
func parseSourceEndpoint(raw json.RawMessage) (string, error) {
	var source string
	if err := json.Unmarshal(raw, &source); err != nil {
		return "", fmt.Errorf("%w: source_endpoint: %v", ErrMalformedClaims, err)
	}
	if !isHTTPSURL(source) {
		return "", fmt.Errorf("%w: source_endpoint is not an https URL (OpenID Federation 1.0 §3.2)", ErrMalformedClaims)
	}
	return source, nil
}

// isHTTPSURL reports whether s is an absolute https URL with a host and
// no fragment.
func isHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Fragment == "" && !strings.ContainsAny(s, " \t\r\n")
}

// maxJSONDepth bounds how deeply refuseDuplicateMembers descends; the
// payload's size is already bounded by jose.DefaultMaxCompactBytes.
const maxJSONDepth = 64

// refuseDuplicateMembers refuses a payload in which any JSON object, at
// any depth, has the same member name twice. encoding/json keeps the
// last one silently, while another implementation may keep the first,
// so two validators could derive different claims — a different
// metadata policy, say — from one signed statement. §6.1.2 forbids
// "Duplicate JSON object member names ... at any of the three levels of
// the metadata_policy Claim data structure"; RFC 7519 §4 lets a JWT
// parser reject duplicate claim names, which this applies at every
// level.
func refuseDuplicateMembers(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := checkJSONValue(dec, 0); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	return nil
}

func checkJSONValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxJSONDepth {
		return errors.New("JSON nested too deeply")
	}
	switch delim {
	case '{':
		return checkJSONObject(dec, depth)
	case '[':
		for dec.More() {
			if err := checkJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

func checkJSONObject(dec *json.Decoder, depth int) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		name, _ := tok.(string)
		if seen[name] {
			return fmt.Errorf("duplicate member name %q", name)
		}
		seen[name] = true
		if err := checkJSONValue(dec, depth+1); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
