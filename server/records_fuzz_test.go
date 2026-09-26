package server

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// FuzzDecodeRecords feeds arbitrary bytes to both record decoders — what
// a corrupted, truncated or foreign-version value handed back by a store
// looks like. Beyond "does not panic": a decoder never accepts a record
// with a version other than recordVersion.
func FuzzDecodeRecords(f *testing.F) {
	f.Add([]byte(`{"v":1,"sub":"user-1","scope":["openid"],"auth_time":"2026-01-01T00:00:00Z"}`))
	f.Add([]byte(`{"v":1,"parameters":{"scope":"\"openid\""},"token_claims":{"x":1}}`))
	f.Add([]byte(`{"v":2}`))
	f.Add([]byte(`{"v":1,"auth_time":"not a time"}`))
	f.Add([]byte(`{"v":"1"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if g, err := decodeGrantRecord(raw); err == nil && g.Version != recordVersion {
			t.Fatalf("decodeGrantRecord accepted version %d from %q", g.Version, raw)
		}
		if r, err := decodeRequestRecord(raw); err == nil && r.Version != recordVersion {
			t.Fatalf("decodeRequestRecord accepted version %d from %q", r.Version, raw)
		}
	})
}

// FuzzGrantRecordRoundTrip checks that everything server persists in a
// grant comes back from decode exactly as it went in — the property
// every token issued from a stored grant depends on. A value encode
// refuses is acceptable (CompleteAuthorization then fails closed); one
// it accepts but alters is not.
func FuzzGrantRecordRoundTrip(f *testing.F) {
	f.Add("user-1", "openid accounts", "urn:acr:1", "nonce-1", "x_hint", []byte(`"v"`), int64(1_700_000_000), int64(0))
	f.Add("user\xff", "openid", "", "", "k", []byte(`{ "a" : [1, 2] }`), int64(0), int64(999))
	f.Add("", "", " ", "n\x00", "", []byte(`null`), int64(-1), int64(1))

	f.Fuzz(func(t *testing.T, sub, scope, acr, nonce, claimName string, claimValue []byte, sec, nsec int64) {
		want := grantRecord{
			Subject: sub, Scope: []string{scope}, ACR: acr, Nonce: nonce,
			AuthTime:    time.Unix(sec, nsec).UTC(),
			TokenClaims: map[string]json.RawMessage{claimName: claimValue},
		}
		raw, err := encodeGrantRecord(want)
		if err != nil {
			return
		}
		got, err := decodeGrantRecord(raw)
		if err != nil {
			t.Fatalf("decode(encode(g)) failed: %v (encoded %q)", err, raw)
		}
		if !got.AuthTime.Equal(want.AuthTime) {
			t.Fatalf("AuthTime round-tripped %v as %v", want.AuthTime, got.AuthTime)
		}
		if got.Subject != want.Subject || got.ACR != want.ACR || got.Nonce != want.Nonce ||
			!reflect.DeepEqual(got.Scope, want.Scope) {
			t.Fatalf("round trip altered string fields: got sub=%q scope=%q acr=%q nonce=%q, want sub=%q scope=%q acr=%q nonce=%q",
				got.Subject, got.Scope, got.ACR, got.Nonce, want.Subject, want.Scope, want.ACR, want.Nonce)
		}
		gotValue, ok := got.TokenClaims[claimName]
		if !ok || !jsonEquivalent(gotValue, claimValue) {
			t.Fatalf("token claim %q round-tripped %q as %q (present=%v)", claimName, claimValue, gotValue, ok)
		}
	})
}

// jsonEquivalent reports whether a and b are the same JSON value,
// ignoring whitespace and key order. Numbers compare by their literal
// text (UseNumber), so one outside float64's range — valid JSON the
// encoder passes through untouched — doesn't fail to decode.
func jsonEquivalent(a, b []byte) bool {
	av, aErr := decodeJSONValue(a)
	bv, bErr := decodeJSONValue(b)
	return aErr == nil && bErr == nil && reflect.DeepEqual(av, bv)
}

func decodeJSONValue(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}
