package pairwise_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
)

var testKey = bytes.Repeat([]byte{0x01, 0x02}, 16)

func newHMAC(t *testing.T) pairwise.Deriver {
	t.Helper()
	d, err := pairwise.NewHMAC(testKey)
	if err != nil {
		t.Fatalf("NewHMAC: %v", err)
	}
	return d
}

func TestHMACDeriverContract(t *testing.T) {
	pairwise.TestDeriverContract(t, newHMAC)
}

func TestHMACKnownAnswers(t *testing.T) {
	raw, err := os.ReadFile("testdata/hmac_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Key, Issuer, Sector, Subject, Body string
		}
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Vectors {
		body := deriveVector(t, v.Key, v.Issuer, v.Sector, v.Subject)
		if body != v.Body {
			t.Errorf("(%s, %q, %q, %.20q) = %q, want %q", v.Key[:8], v.Issuer, v.Sector, v.Subject, body, v.Body)
		}
		if len(body) != pairwise.HMACBodyLength {
			t.Errorf("body length %d, want %d", len(body), pairwise.HMACBodyLength)
		}
	}
}

// deriveVector derives the body for one known-answer vector.
func deriveVector(t *testing.T, hexKey, issuer, sector, subject string) string {
	t.Helper()
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pairwise.NewHMAC(key)
	if err != nil {
		t.Fatalf("NewHMAC: %v", err)
	}
	in, err := pairwise.NewInput(issuer, sector, subject)
	if err != nil {
		t.Fatalf("NewInput: %v", err)
	}
	body, err := d.DerivePairwiseSubject(context.Background(), in)
	if err != nil {
		t.Fatalf("DerivePairwiseSubject: %v", err)
	}
	return body
}

func TestNewHMACRefusesWeakKeys(t *testing.T) {
	for name, key := range map[string][]byte{
		"empty":    nil,
		"short":    testKey[:31],
		"long":     append(append([]byte(nil), testKey...), 0x03),
		"all zero": make([]byte, 32),
		"repeated": bytes.Repeat([]byte{0x5a}, 32),
	} {
		if _, err := pairwise.NewHMAC(key); err == nil {
			t.Errorf("NewHMAC(%s key) succeeded, want an error", name)
		}
	}
}

func TestNewHMACCopiesTheKey(t *testing.T) {
	key := append([]byte(nil), testKey...)
	d, err := pairwise.NewHMAC(key)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := pairwise.NewInput("https://op.example", "rp.example", "user-1")
	before, _ := d.DerivePairwiseSubject(context.Background(), in)
	key[0] ^= 0xff
	if after, _ := d.DerivePairwiseSubject(context.Background(), in); after != before {
		t.Error("changing the caller's key slice changed the Deriver's output")
	}
}

func TestNewHMACDeclaresCustodyOnlyWhenGiven(t *testing.T) {
	undeclared, err := pairwise.NewHMAC(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := undeclared.KeyCustody(); got != (keys.KeyCustody{}) {
		t.Errorf("an HMAC Deriver with no custody declared reports %+v, want none", got)
	}
	want := keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}
	d, err := pairwise.NewHMAC(testKey, keys.DeclareCustody(want))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.KeyCustody(); got != want {
		t.Errorf("custody = %+v, want %+v", got, want)
	}
	if _, ok := any(d).(pairwise.Lookup); ok {
		t.Error("the HMAC Deriver implements Lookup")
	}
}

func TestHMACHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in, _ := pairwise.NewInput("https://op.example", "rp.example", "user-1")
	if body, err := newHMAC(t).DerivePairwiseSubject(ctx, in); err == nil {
		t.Errorf("DerivePairwiseSubject with a cancelled context = %q, want an error", body)
	}
}

func TestNewPrefix(t *testing.T) {
	for _, ok := range []string{"", "ppid:", "x", strings.Repeat("a", 16), "!~"} {
		p, err := pairwise.NewPrefix(ok)
		if err != nil || !p.IsSet() || p.String() != ok {
			t.Errorf("NewPrefix(%q) = %v (set %v), %v", ok, p, p.IsSet(), err)
		}
	}
	for _, bad := range []string{strings.Repeat("a", 17), "pp id", "ppid:\n", "ppid\x7f", "ppïd"} {
		if p, err := pairwise.NewPrefix(bad); err == nil {
			t.Errorf("NewPrefix(%q) = %v, want an error", bad, p)
		}
	}
	if (pairwise.Prefix{}).IsSet() {
		t.Error("the zero Prefix is set")
	}
}

func TestNewInput(t *testing.T) {
	long := strings.Repeat("a", pairwise.MaxInputLength+1)
	bad := []struct{ issuer, sector, subject string }{
		{"", "rp.example", "u"},
		{"https://op.example", "", "u"},
		{"https://op.example", "rp.example", ""},
		{long, "rp.example", "u"},
		{"https://op.example", long, "u"},
		{"https://op.example", "rp.example", strings.Repeat("u", 256)},
		{"https://op.example", "rp.example", "u\x00"},
		{"https://op.example", "rp.example", "ü"},
		{"https://op.example\n", "rp.example", "u"},
		{"https://op.example", "rp\u0085.example", "u"}, // C1 control (NEL), valid UTF-8
		{"https://op.example", "rp\x7f.example", "u"},   // DEL
		{"https://op.example", "rp.example\xff", "u"},
	}
	for _, b := range bad {
		if in, err := pairwise.NewInput(b.issuer, b.sector, b.subject); err == nil {
			t.Errorf("NewInput(%.30q, %.30q, %.30q) = %v, want an error", b.issuer, b.sector, b.subject, in)
		}
	}
	in, err := pairwise.NewInput("https://op.example/ü", "rp.example", strings.Repeat("u", 255))
	if err != nil || in.Issuer() != "https://op.example/ü" || in.Sector() != "rp.example" || len(in.Subject()) != 255 || in.IsZero() {
		t.Errorf("NewInput = %v, %v", in, err)
	}
}

func TestCheckBody(t *testing.T) {
	for _, ok := range []string{"a", strings.Repeat("a", pairwise.MaxBodyLength), "A-_~"} {
		if err := pairwise.CheckBody(ok); err != nil {
			t.Errorf("CheckBody(%.20q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", pairwise.MaxBodyLength+1), "a b", "a\n", "ä"} {
		if err := pairwise.CheckBody(bad); err == nil {
			t.Errorf("CheckBody(%.20q) succeeded", bad)
		}
	}
}

func FuzzNewPrefix(f *testing.F) {
	for _, seed := range []string{"", "ppid:", strings.Repeat("a", 17), "a b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := pairwise.NewPrefix(s)
		if err != nil {
			return
		}
		if !p.IsSet() || p.String() != s || len(s) > pairwise.MaxPrefixLength {
			t.Fatalf("NewPrefix(%q) = %v", s, p)
		}
		for i := range len(s) {
			if s[i] < 0x21 || s[i] > 0x7e {
				t.Fatalf("NewPrefix(%q) accepted byte 0x%02x", s, s[i])
			}
		}
	})
}

// FuzzHMACDeterministicAndInjective: the same Input always derives the
// same valid body, and Inputs differing in any field derive different
// bodies (a collision would be a broken encoding, not an HMAC collision).
func FuzzHMACDeterministicAndInjective(f *testing.F) {
	f.Add("https://op.example", "rp.example", "user-1", "rp.exampleuser", "-1")
	f.Add("a", "bc", "d", "b", "cd")
	d, err := pairwise.NewHMAC(testKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, issuer, sector, subject, sector2, subject2 string) {
		in, err := pairwise.NewInput(issuer, sector, subject)
		if err != nil {
			return
		}
		ctx := context.Background()
		body, err := d.DerivePairwiseSubject(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if err := pairwise.CheckBody(body); err != nil {
			t.Fatal(err)
		}
		if again, _ := d.DerivePairwiseSubject(ctx, in); again != body {
			t.Fatalf("not deterministic: %q then %q", body, again)
		}
		other, err := pairwise.NewInput(issuer, sector2, subject2)
		if err != nil || (sector2 == sector && subject2 == subject) {
			return
		}
		if body2, _ := d.DerivePairwiseSubject(ctx, other); body2 == body {
			t.Fatalf("(%q, %q) and (%q, %q) both derived %q", sector, subject, sector2, subject2, body)
		}
	})
}

// TestDeriversRefuseTextKeys: a key made entirely of printable text (a
// passphrase, or a hex or base64 key not yet decoded) is refused; one
// non-text byte is enough to accept it.
func TestDeriversRefuseTextKeys(t *testing.T) {
	random := bytes.Repeat([]byte{0x01, 0xfe}, 16)
	for name, key := range map[string][]byte{
		"passphrase":      []byte("my-super-secret-pairwise-key-123"),
		"hex, undecoded":  []byte("0123456789abcdef0123456789abcdef"),
		"with whitespace": []byte("correct horse battery staple\n\tok"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pairwise.NewHMAC(key[:32]); err == nil || !strings.Contains(err.Error(), "printable text") {
				t.Errorf("NewHMAC(%q) = %v, want refused as text", key[:32], err)
			}
			if _, err := pairwise.NewReversible(random, key[:32]); err == nil || !strings.Contains(err.Error(), "printable text") {
				t.Errorf("NewReversible(_, %q) = %v, want refused as text", key[:32], err)
			}
			if _, err := pairwise.NewReversible(key[:32], random); err == nil || !strings.Contains(err.Error(), "printable text") {
				t.Errorf("NewReversible(%q, _) = %v, want refused as text", key[:32], err)
			}
		})
	}
	almost := []byte("my-super-secret-pairwise-key-12\x00")
	if _, err := pairwise.NewHMAC(almost); err != nil {
		t.Errorf("NewHMAC with one non-text byte = %v, want accepted", err)
	}
}
