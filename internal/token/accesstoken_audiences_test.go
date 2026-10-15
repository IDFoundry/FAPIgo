package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestAccessTokenAudiences covers AccessTokenParams.Audiences: "aud" is
// a string for one audience and an array for several (RFC 7519 §4.1.3),
// replacing Audience, and validates against either.
func TestAccessTokenAudiences(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	for name, tc := range map[string]struct {
		audience  string
		audiences []string
		want      any
	}{
		"audience only": {audience: "https://rs.example", want: "https://rs.example"},
		"one":           {audience: "https://ignored.example", audiences: []string{"https://rs.example"}, want: "https://rs.example"},
		"several":       {audiences: []string{"https://other.example", "https://rs.example"}, want: []any{"https://other.example", "https://rs.example"}},
	} {
		t.Run(name, func(t *testing.T) {
			p := baseAccessTokenParams(key, now, time.Minute)
			p.Audience, p.Audiences = tc.audience, tc.audiences
			tok, _, err := IssueAccessToken(p)
			if err != nil {
				t.Fatalf("IssueAccessToken: %v", err)
			}
			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
			if err != nil {
				t.Fatal(err)
			}
			var claims struct {
				Aud any `json:"aud"`
			}
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(claims.Aud, tc.want) {
				t.Fatalf("aud = %#v, want %#v", claims.Aud, tc.want)
			}
			parsed, err := ParseAccessToken(tok)
			if err != nil {
				t.Fatalf("ParseAccessToken: %v", err)
			}
			if _, err := parsed.Validate(&key.PublicKey, baseAccessTokenPolicy(now)); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestAccessTokenAudiencesValidation(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := baseAccessTokenParams(key, now, time.Minute)
	p.Audiences = []string{"https://rs.example", ""}
	if _, _, err := IssueAccessToken(p); err == nil {
		t.Fatal("IssueAccessToken accepted an empty audience among Audiences")
	}
	p = baseAccessTokenParams(key, now, time.Minute)
	p.Audience = ""
	if _, _, err := IssueAccessToken(p); err == nil {
		t.Fatal("IssueAccessToken accepted no audience")
	}
}

func TestAccessTokenValidateAdditionalAudiences(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	p := baseAccessTokenParams(key, now, time.Minute)
	p.Audience = "https://as.example"
	tok, _, err := IssueAccessToken(p)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	parsed, err := ParseAccessToken(tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	policy := baseAccessTokenPolicy(now)
	if _, err := parsed.Validate(&key.PublicKey, policy); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Validate without additional = %v, want ErrAudienceMismatch", err)
	}
	policy.AdditionalAudiences = []string{"", "https://other.example"}
	if _, err := parsed.Validate(&key.PublicKey, policy); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("Validate with unrelated additional = %v, want ErrAudienceMismatch", err)
	}
	policy.AdditionalAudiences = []string{"https://other.example", "https://as.example"}
	if _, err := parsed.Validate(&key.PublicKey, policy); err != nil {
		t.Fatalf("Validate with matching additional: %v", err)
	}
}
