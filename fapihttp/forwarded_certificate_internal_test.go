package fapihttp

import "testing"

// TestParseByteSequenceRefusesPaddingAlone: a Byte Sequence of nothing
// but "=" padding is as empty as "::" and is refused as such, rather
// than read as zero bytes for x509.ParseCertificate to refuse later.
func TestParseByteSequenceRefusesPaddingAlone(t *testing.T) {
	for _, value := range []string{":=:", ":==:", " :==: "} {
		if der, err := parseByteSequence(value); err == nil {
			t.Errorf("parseByteSequence(%q) = %x, nil; want an error", value, der)
		}
	}
}
