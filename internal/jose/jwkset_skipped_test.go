package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestParseJWKSetWithSkipsReportsWhy: an entry ParseJWKSet skips is
// reported with its kid and the reason, an encryption key isn't
// reported, and the usable entries are the ones ParseJWKSet returns.
func TestParseJWKSetWithSkipsReportsWhy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	x, y := b64(key.X.FillBytes(make([]byte, 32))), b64(key.Y.FillBytes(make([]byte, 32)))
	set := fmt.Sprintf(`{"keys":[
		{"kty":"EC","crv":"P-256","kid":"good","x":%q,"y":%q},
		{"kty":"EC","crv":"P-256","kid":"short","x":%q,"y":%q},
		{"kty":"EC","crv":"P-256","kid":"enc","use":"enc","x":%q,"y":%q},
		{"kty":"oct","kid":"secret","k":"c2VjcmV0"},
		{"kty":"EC","KID":"case"}
	]}`, x, y, b64(make([]byte, 31)), y, x, y)

	keys, skipped, err := ParseJWKSetWithSkips([]byte(set))
	if err != nil {
		t.Fatalf("ParseJWKSetWithSkips: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyID != "good" {
		t.Fatalf("keys = %+v, want only the entry with kid good", keys)
	}
	plain, err := ParseJWKSet([]byte(set))
	if err != nil || len(plain) != 1 || plain[0].KeyID != "good" {
		t.Fatalf("ParseJWKSet = %+v, %v; want the same usable entry", plain, err)
	}
	if len(skipped) != 3 {
		t.Fatalf("skipped = %+v, want the short, oct and case-variant entries, not the encryption key", skipped)
	}
	if skipped[0].KeyID != "short" || !errors.Is(skipped[0].Reason, ErrCoordinateLength) {
		t.Errorf("skipped[0] = %+v, want kid short with ErrCoordinateLength", skipped[0])
	}
	if skipped[1].KeyID != "secret" || !strings.Contains(skipped[1].Reason.Error(), `kty "oct"`) {
		t.Errorf("skipped[1] = %+v, want kid secret refused as an unsupported key", skipped[1])
	}
	if skipped[2].KeyID != "" || skipped[2].Reason == nil {
		t.Errorf("skipped[2] = %+v, want an entry that didn't decode, with no kid", skipped[2])
	}

	if got := SkippedKeyReason(skipped, "short"); !strings.Contains(got, `entry with kid "short" was skipped`) || !strings.Contains(got, "octets") {
		t.Errorf("SkippedKeyReason(short) = %q, want the entry's coordinate-length reason", got)
	}
	if got := SkippedKeyReason(skipped, "good"); got != "" {
		t.Errorf("SkippedKeyReason(good) = %q, want none: that entry wasn't skipped", got)
	}
	if got := SkippedKeysReason(skipped); !strings.HasPrefix(got, "; 3 JWK Set entries were skipped (") || !strings.Contains(got, `kid "secret"`) {
		t.Errorf("SkippedKeysReason = %q, want all three named", got)
	}
	if got := SkippedKeysReason(nil); got != "" {
		t.Errorf("SkippedKeysReason(nil) = %q, want none", got)
	}
}

// TestSkippedKeysReasonIsBounded: the set's publisher chooses how many
// entries are skipped and how long their kids are, so a reason names at
// most maxSkipReasons of them and quotes at most maxQuotedKeyIDBytes of
// each kid.
func TestSkippedKeysReasonIsBounded(t *testing.T) {
	long := strings.Repeat("k", 10_000)
	skipped := make([]SkippedJWK, 1000)
	for i := range skipped {
		skipped[i] = SkippedJWK{KeyID: long, Reason: errors.New("unusable")}
	}
	for name, got := range map[string]string{
		"SkippedKeysReason": SkippedKeysReason(skipped),
		"SkippedKeyReason":  SkippedKeyReason(skipped, long),
	} {
		if len(got) > 1024 {
			t.Errorf("%s is %d bytes, want it bounded", name, len(got))
		}
		if !strings.Contains(got, "and 997 more") {
			t.Errorf("%s = %.200q…, want the entries past the first %d counted, not named", name, got, maxSkipReasons)
		}
	}
}
