package strictjson

import (
	"strings"
	"testing"
)

// TestASCIIFoldMatchesFoldKey: scanMembers folds a name of ASCII bytes
// to upper case in place, which is FoldKey's result for every ASCII
// byte, "k" and "s" included (the least of each fold orbit, with U+212A
// and U+017F, is upper case).
func TestASCIIFoldMatchesFoldKey(t *testing.T) {
	for c := 0x20; c < 0x80; c++ {
		if c == '"' || c == '\\' {
			continue
		}
		want := FoldKey(string(rune(c)))
		s := memberScanner{data: []byte(`"` + string(rune(c)) + `"`)}
		span, ok := s.name()
		if !ok {
			t.Fatalf("name(%q) failed", rune(c))
		}
		if got := string(s.folded[span.start:span.end]); got != want {
			t.Errorf("fold of %q = %q, FoldKey = %q", rune(c), got, want)
		}
	}
}

// scanAndWalkCases are documents whose verdict scanMembers and the
// walker must agree on: each well-formed shape, each repeat the walker
// refuses, and each kind of malformed JSON.
var scanAndWalkCases = []string{
	`{}`, `[]`, `"s"`, `1`, `-0.5e+10`, `true`, `false`, `null`, ` {"a":1} `,
	`{"a":1,"b":[1,2,{"a":3}],"c":{"a":{"a":null}}}`,
	`{"a":1}{"a":1,"a":2}`, `1 2`, `123abc`, `truex`, `{"a":1}}`,
	`{"a":1,"a":2}`, `{"kid":1,"KID":2}`, `{"k":1,"K":2}`, `{"s":1,"ſ":2}`,
	`{"kid":1,"kid":2}`, `{"aé":1,"AÉ":2}`, "{\"a\xff\":1,\"a\xfe\":2}",
	`{"x":{"a":1},"y":{"a":1}}`, `[{"a":1},{"a":1}]`,
	`{"a"}`, `{"a":}`, `{"a":1,}`, `[1,]`, `{,}`, `{"a" 1}`, `{1:1}`, `[1 2]`,
	`"\x"`, `"\u12"`, `"\u12g4"`, "\"a\x01\"", `"abc`, `{"a":1`, `[1`, `[`, `{`, ``, `   `,
	`01`, `-`, `1.`, `.5`, `1e`, `1e+`, `+1`, `nul`, `tru`, `NaN`,
	strings.Repeat("[", MaxNestingDepth) + strings.Repeat("]", MaxNestingDepth),
	strings.Repeat("[", MaxNestingDepth+1) + strings.Repeat("]", MaxNestingDepth+1),
	strings.Repeat(`{"a":`, MaxNestingDepth) + "1" + strings.Repeat("}", MaxNestingDepth),
	strings.Repeat(`{"a":`, MaxNestingDepth+1) + "1" + strings.Repeat("}", MaxNestingDepth+1),
	manyMembers(smallObjectMembers+5, -1), manyMembers(smallObjectMembers+5, 3), manyMembers(smallObjectMembers+5, smallObjectMembers+2),
}

// manyMembers is an object of n members named m0, m1, ..., with member
// repeat (if not -1) named again at the end.
func manyMembers(n, repeat int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"m` + itoa(i) + `":0`)
	}
	if repeat >= 0 {
		b.WriteString(`,"M` + itoa(repeat) + `":1`)
	}
	b.WriteString("}")
	return b.String()
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// TestScanMembersMatchesWalker: scanMembers accepts exactly what the
// walker accepts, for each case above.
func TestScanMembersMatchesWalker(t *testing.T) {
	for _, doc := range scanAndWalkCases {
		scanned, walked := scanMembers([]byte(doc)), walkMembers([]byte(doc))
		if scanned != (walked == nil) {
			t.Errorf("%.80q: scanMembers = %v, walker = %v", doc, scanned, walked)
		}
	}
}

// FuzzScanMembersMatchesWalker: whatever the input, scanMembers accepts
// it exactly when the walker does. Accepting more would let a repeated
// member or malformed JSON through CheckDuplicateMembers; accepting less
// only costs the walker's time, but is checked too, so the fast path
// keeps covering the documents it is for.
func FuzzScanMembersMatchesWalker(f *testing.F) {
	for _, doc := range scanAndWalkCases {
		f.Add([]byte(doc))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		scanned, walked := scanMembers(data), walkMembers(data)
		if scanned != (walked == nil) {
			t.Fatalf("%q: scanMembers = %v, walker = %v", data, scanned, walked)
		}
	})
}

// benchmarkDocuments are the header shapes #921 measured, each about
// 12 KiB (about the largest header a 16 KiB compact JWS carries), and a
// typical DPoP proof header.
func benchmarkDocuments() map[string][]byte {
	var members, numbers, objects strings.Builder
	members.WriteString(`{"alg":"ES256"`)
	for i := 0; members.Len() < 12_000; i++ {
		members.WriteString(`,"m` + itoa(i) + `":1`)
	}
	members.WriteString("}")
	numbers.WriteString(`{"alg":"ES256","x":[1`)
	for numbers.Len() < 12_000 {
		numbers.WriteString(",1")
	}
	numbers.WriteString("]}")
	objects.WriteString(`{"alg":"ES256","x":[{}`)
	for objects.Len() < 12_000 {
		objects.WriteString(",{}")
	}
	objects.WriteString("]}")
	return map[string][]byte{
		"members":  []byte(members.String()),
		"numbers":  []byte(numbers.String()),
		"objects":  []byte(objects.String()),
		"dpop-jwk": []byte(`{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}}`),
	}
}

// BenchmarkCheckDuplicateMembers compares CheckDuplicateMembers, which
// scans first, with the json.Decoder walker alone, which it ran before.
func BenchmarkCheckDuplicateMembers(b *testing.B) {
	for name, doc := range benchmarkDocuments() {
		for _, impl := range []struct {
			name  string
			check func([]byte) error
		}{{"walker", walkMembers}, {"scan", CheckDuplicateMembers}} {
			b.Run(name+"/"+impl.name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(doc)))
				for b.Loop() {
					if err := impl.check(doc); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
