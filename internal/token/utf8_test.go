package token

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// TestAccessTokenRefusesInvalidUTF8Claims covers RFC 8725 §3.7 and RFC
// 7519 §7.2: a signed access token whose "sub" carries a raw 0xff byte,
// or an unpaired surrogate escape, is refused rather than read as a
// subject starting with U+FFFD — which both would decode to, so two
// different signed tokens would name the same subject.
func TestAccessTokenRefusesInvalidUTF8Claims(t *testing.T) {
	key := generateKey(t)
	now := time.Unix(1_800_000_000, 0)
	for name, sub := range map[string]string{
		"raw 0xff byte":       "\xffalice",
		"lone \\ud800 escape": `\ud800alice`,
		"lone \\udfff escape": `\udfffalice`,
		"high then non-low":   `\ud800Alice`,
	} {
		t.Run(name, func(t *testing.T) {
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"at+jwt"}`))
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://as.example","sub":"` + sub + `","aud":"https://rs.example","client_id":"c","exp":1800000060,"iat":1800000000,"jti":"j"}`))
			input := header + "." + payload
			parsed, err := ParseAccessToken(input + "." + signRaw(t, key, input))
			if err == nil {
				v, verr := parsed.Validate(&key.PublicKey, AccessTokenValidatePolicy{
					ExpectedIssuer: "https://as.example", ExpectedAudience: "https://rs.example",
					Algorithm: fapi.ES256, Now: now, MaxLifetime: time.Hour,
				})
				t.Fatalf("ParseAccessToken = nil error (Validate: Subject %q, %v), want refusal", v.Subject, verr)
			}
			if !errors.Is(err, jose.ErrMalformed) {
				t.Errorf("ParseAccessToken = %v, want jose.ErrMalformed", err)
			}
		})
	}
}
