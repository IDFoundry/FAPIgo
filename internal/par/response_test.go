package par

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodeResultRoundTrip(t *testing.T) {
	want := PushResult{RequestURI: "urn:ietf:params:oauth:request_uri:abc123", ExpiresIn: 90 * time.Second}
	body, err := EncodeResult(want)
	if err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}
	got, err := DecodeResult(body)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if got != want {
		t.Fatalf("DecodeResult(EncodeResult(%+v)) = %+v", want, got)
	}
}

func TestDecodeResultAcceptsThirdPartyFormat(t *testing.T) {
	// A third-party AS's request_uri need not use RequestURIPrefix.
	body := []byte(`{"request_uri":"https://as.example/par/abc","expires_in":60}`)
	got, err := DecodeResult(body)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if got.RequestURI != "https://as.example/par/abc" {
		t.Fatalf("RequestURI = %q, want %q", got.RequestURI, "https://as.example/par/abc")
	}
}

func TestEncodeResultRejectsMissingRequestURI(t *testing.T) {
	_, err := EncodeResult(PushResult{ExpiresIn: 60 * time.Second})
	if !errors.Is(err, ErrMissingRequestURI) {
		t.Fatalf("EncodeResult(no request_uri) = %v, want ErrMissingRequestURI", err)
	}
}

func TestEncodeResultRejectsNonPositiveExpiresIn(t *testing.T) {
	_, err := EncodeResult(PushResult{RequestURI: "urn:x", ExpiresIn: 0})
	if !errors.Is(err, ErrInvalidExpiresIn) {
		t.Fatalf("EncodeResult(expires_in=0) = %v, want ErrInvalidExpiresIn", err)
	}
}

func TestDecodeResultRejectsMissingRequestURI(t *testing.T) {
	_, err := DecodeResult([]byte(`{"expires_in":60}`))
	if !errors.Is(err, ErrMissingRequestURI) {
		t.Fatalf("DecodeResult(no request_uri) = %v, want ErrMissingRequestURI", err)
	}
}

func TestDecodeResultRejectsNonPositiveExpiresIn(t *testing.T) {
	cases := []string{
		`{"request_uri":"urn:x","expires_in":0}`,
		`{"request_uri":"urn:x","expires_in":-5}`,
	}
	for _, c := range cases {
		if _, err := DecodeResult([]byte(c)); !errors.Is(err, ErrInvalidExpiresIn) {
			t.Fatalf("DecodeResult(%s) = %v, want ErrInvalidExpiresIn", c, err)
		}
	}
}

// TestDecodeResultIgnoresUnknownField covers RFC 6749 §5.1's "MUST
// ignore unrecognized value names and extra parameters" — a member
// beyond request_uri/expires_in must not fail parsing.
func TestDecodeResultIgnoresUnknownField(t *testing.T) {
	body := []byte(`{"request_uri":"urn:x","expires_in":60,"unexpected":"value"}`)
	got, err := DecodeResult(body)
	if err != nil {
		t.Fatalf("DecodeResult(unknown field) = %v, want nil error", err)
	}
	if got.RequestURI != "urn:x" || got.ExpiresIn != 60*time.Second {
		t.Fatalf("DecodeResult(unknown field) = %+v, want request_uri/expires_in still parsed", got)
	}
}

func TestDecodeResultRejectsOversized(t *testing.T) {
	huge := []byte(`{"request_uri":"` + strings.Repeat("a", maxResponseBytes+1) + `","expires_in":60}`)
	if _, err := DecodeResult(huge); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("DecodeResult(oversized) = %v, want ErrResponseTooLarge", err)
	}
}

func TestEncodeDecodeErrorResponseRoundTrip(t *testing.T) {
	want := ErrorResponse{Code: "invalid_request", Description: "missing redirect_uri", URI: "https://as.example/errors/invalid_request"}
	body, err := EncodeErrorResponse(want)
	if err != nil {
		t.Fatalf("EncodeErrorResponse: %v", err)
	}
	got, err := DecodeErrorResponse(body)
	if err != nil {
		t.Fatalf("DecodeErrorResponse: %v", err)
	}
	if got != want {
		t.Fatalf("DecodeErrorResponse(EncodeErrorResponse(%+v)) = %+v", want, got)
	}
}

func TestEncodeErrorResponseOmitsOptionalFields(t *testing.T) {
	body, err := EncodeErrorResponse(ErrorResponse{Code: "invalid_request"})
	if err != nil {
		t.Fatalf("EncodeErrorResponse: %v", err)
	}
	if strings.Contains(string(body), "error_description") || strings.Contains(string(body), "error_uri") {
		t.Fatalf("EncodeErrorResponse output includes empty optional fields: %s", body)
	}
}

func TestEncodeErrorResponseRejectsMissingCode(t *testing.T) {
	_, err := EncodeErrorResponse(ErrorResponse{Description: "x"})
	if !errors.Is(err, ErrMissingErrorCode) {
		t.Fatalf("EncodeErrorResponse(no code) = %v, want ErrMissingErrorCode", err)
	}
}

func TestDecodeErrorResponseRejectsMissingCode(t *testing.T) {
	_, err := DecodeErrorResponse([]byte(`{"error_description":"x"}`))
	if !errors.Is(err, ErrMissingErrorCode) {
		t.Fatalf("DecodeErrorResponse(no code) = %v, want ErrMissingErrorCode", err)
	}
}

func TestDecodeErrorResponseRejectsOversized(t *testing.T) {
	huge := []byte(`{"error":"` + strings.Repeat("a", maxResponseBytes+1) + `"}`)
	if _, err := DecodeErrorResponse(huge); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("DecodeErrorResponse(oversized) = %v, want ErrResponseTooLarge", err)
	}
}

// TestDecodeErrorResponseIgnoresUnknownField covers RFC 6749 §5.2 the
// same way TestDecodeResultIgnoresUnknownField covers §5.1 — a member
// beyond error/error_description/error_uri must not fail parsing.
func TestDecodeErrorResponseIgnoresUnknownField(t *testing.T) {
	body := []byte(`{"error":"invalid_request","unexpected":"value"}`)
	got, err := DecodeErrorResponse(body)
	if err != nil {
		t.Fatalf("DecodeErrorResponse(unknown field) = %v, want nil error", err)
	}
	if got.Code != "invalid_request" {
		t.Fatalf("DecodeErrorResponse(unknown field) = %+v, want error still parsed", got)
	}
}
