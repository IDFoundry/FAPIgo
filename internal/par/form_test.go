package par

import (
	"errors"
	"strings"
	"testing"
)

func TestEncodeDecodeFormRoundTrip(t *testing.T) {
	params := map[string]string{
		"response_type": "code",
		"client_id":     "client-123",
		"redirect_uri":  "https://rp.example/callback",
		"scope":         "openid accounts",
		"state":         "opaque state with spaces",
	}
	body := EncodeForm(params)

	decoded, err := DecodeForm(body)
	if err != nil {
		t.Fatalf("DecodeForm: %v", err)
	}
	if len(decoded) != len(params) {
		t.Fatalf("len(decoded) = %d, want %d", len(decoded), len(params))
	}
	for k, v := range params {
		if decoded[k] != v {
			t.Fatalf("decoded[%q] = %q, want %q", k, decoded[k], v)
		}
	}
}

func TestEncodeFormIsDeterministic(t *testing.T) {
	params := map[string]string{"b": "2", "a": "1", "c": "3"}
	first := string(EncodeForm(params))
	for i := 0; i < 5; i++ {
		if got := string(EncodeForm(params)); got != first {
			t.Fatalf("EncodeForm output not deterministic: %q vs %q", got, first)
		}
	}
}

func TestDecodeFormRejectsDuplicateParameter(t *testing.T) {
	_, err := DecodeForm([]byte("client_id=a&client_id=b"))
	if !errors.Is(err, ErrDuplicateParameter) {
		t.Fatalf("DecodeForm(duplicate) = %v, want ErrDuplicateParameter", err)
	}
}

func TestDecodeFormRejectsMalformed(t *testing.T) {
	_, err := DecodeForm([]byte("%zz=value"))
	if !errors.Is(err, ErrMalformedForm) {
		t.Fatalf("DecodeForm(malformed) = %v, want ErrMalformedForm", err)
	}
}

func TestDecodeFormRejectsOversized(t *testing.T) {
	huge := []byte(strings.Repeat("a", maxFormBytes+1))
	_, err := DecodeForm(huge)
	if !errors.Is(err, ErrFormTooLarge) {
		t.Fatalf("DecodeForm(oversized) = %v, want ErrFormTooLarge", err)
	}
}

func TestDecodeFormAcceptsEmptyBody(t *testing.T) {
	decoded, err := DecodeForm(nil)
	if err != nil {
		t.Fatalf("DecodeForm(nil): %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("len(decoded) = %d, want 0", len(decoded))
	}
}
