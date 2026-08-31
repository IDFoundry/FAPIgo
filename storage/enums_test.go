package storage

import "testing"

func TestClientAuthMethodStringRoundTrip(t *testing.T) {
	methods := []ClientAuthMethod{
		ClientAuthMethodPrivateKeyJWT, ClientAuthMethodSelfSignedTLSClientAuth, ClientAuthMethodTLSClientAuth,
		ClientAuthMethodTLSClientAuthSANDNS, ClientAuthMethodTLSClientAuthSANURI,
		ClientAuthMethodTLSClientAuthSANIP, ClientAuthMethodTLSClientAuthSANEmail,
	}
	for _, m := range methods {
		s := m.String()
		if s == "" {
			t.Fatalf("%v.String() = %q, want non-empty", m, s)
		}
		got, err := ParseClientAuthMethod(s)
		if err != nil {
			t.Fatalf("ParseClientAuthMethod(%q) error: %v", s, err)
		}
		if got != m {
			t.Fatalf("ParseClientAuthMethod(%q) = %v, want %v", s, got, m)
		}
		if !m.IsValid() {
			t.Fatalf("%v.IsValid() = false, want true", m)
		}
	}
}

func TestClientAuthMethodZeroValueIsPrivateKeyJWT(t *testing.T) {
	// Unlike fapi's algorithm enums, ClientAuthMethod's zero value is a
	// real, meaningful default (see its own doc comment) — not a
	// reserved invalid marker — so it round-trips like any other value.
	var m ClientAuthMethod
	if m != ClientAuthMethodPrivateKeyJWT {
		t.Fatalf("zero value = %v, want ClientAuthMethodPrivateKeyJWT", m)
	}
	if !m.IsValid() {
		t.Fatalf("zero value IsValid() = false, want true")
	}
	if m.String() != "private_key_jwt" {
		t.Fatalf("zero value String() = %q, want %q", m.String(), "private_key_jwt")
	}
}

func TestClientAuthMethodOutOfRangeInvalid(t *testing.T) {
	m := ClientAuthMethod(99)
	if m.IsValid() {
		t.Fatalf("ClientAuthMethod(99).IsValid() = true, want false")
	}
	if s := m.String(); s != "" {
		t.Fatalf("ClientAuthMethod(99).String() = %q, want empty", s)
	}
}

func TestParseClientAuthMethodRejectsUnrecognized(t *testing.T) {
	for _, s := range []string{"", "PRIVATE_KEY_JWT", "none", "self_signed_tls_client_auth "} {
		if _, err := ParseClientAuthMethod(s); err == nil {
			t.Fatalf("ParseClientAuthMethod(%q) = nil error, want error", s)
		}
	}
}

func TestSenderConstrainStringRoundTrip(t *testing.T) {
	for _, s := range []SenderConstrain{SenderConstrainDPoP, SenderConstrainMTLS} {
		str := s.String()
		if str == "" {
			t.Fatalf("%v.String() = %q, want non-empty", s, str)
		}
		got, err := ParseSenderConstrain(str)
		if err != nil {
			t.Fatalf("ParseSenderConstrain(%q) error: %v", str, err)
		}
		if got != s {
			t.Fatalf("ParseSenderConstrain(%q) = %v, want %v", str, got, s)
		}
		if !s.IsValid() {
			t.Fatalf("%v.IsValid() = false, want true", s)
		}
	}
}

func TestSenderConstrainZeroValueIsDPoP(t *testing.T) {
	var s SenderConstrain
	if s != SenderConstrainDPoP {
		t.Fatalf("zero value = %v, want SenderConstrainDPoP", s)
	}
	if !s.IsValid() {
		t.Fatalf("zero value IsValid() = false, want true")
	}
	if s.String() != "dpop" {
		t.Fatalf("zero value String() = %q, want %q", s.String(), "dpop")
	}
}

func TestSenderConstrainOutOfRangeInvalid(t *testing.T) {
	s := SenderConstrain(99)
	if s.IsValid() {
		t.Fatalf("SenderConstrain(99).IsValid() = true, want false")
	}
	if str := s.String(); str != "" {
		t.Fatalf("SenderConstrain(99).String() = %q, want empty", str)
	}
}

func TestParseSenderConstrainRejectsUnrecognized(t *testing.T) {
	for _, s := range []string{"", "DPOP", "mTLS", "none"} {
		if _, err := ParseSenderConstrain(s); err == nil {
			t.Fatalf("ParseSenderConstrain(%q) = nil error, want error", s)
		}
	}
}

func TestBackchannelTokenDeliveryModeStringRoundTrip(t *testing.T) {
	for _, m := range []BackchannelTokenDeliveryMode{BackchannelTokenDeliveryModePoll, BackchannelTokenDeliveryModePing} {
		s := m.String()
		if s == "" {
			t.Fatalf("%v.String() = %q, want non-empty", m, s)
		}
		got, err := ParseBackchannelTokenDeliveryMode(s)
		if err != nil {
			t.Fatalf("ParseBackchannelTokenDeliveryMode(%q) error: %v", s, err)
		}
		if got != m {
			t.Fatalf("ParseBackchannelTokenDeliveryMode(%q) = %v, want %v", s, got, m)
		}
		if !m.IsValid() {
			t.Fatalf("%v.IsValid() = false, want true", m)
		}
	}
}

func TestBackchannelTokenDeliveryModeZeroValueIsPoll(t *testing.T) {
	var m BackchannelTokenDeliveryMode
	if m != BackchannelTokenDeliveryModePoll {
		t.Fatalf("zero value = %v, want BackchannelTokenDeliveryModePoll", m)
	}
	if !m.IsValid() {
		t.Fatalf("zero value IsValid() = false, want true")
	}
	if m.String() != "poll" {
		t.Fatalf("zero value String() = %q, want %q", m.String(), "poll")
	}
}

func TestBackchannelTokenDeliveryModeOutOfRangeInvalid(t *testing.T) {
	m := BackchannelTokenDeliveryMode(99)
	if m.IsValid() {
		t.Fatalf("BackchannelTokenDeliveryMode(99).IsValid() = true, want false")
	}
	if s := m.String(); s != "" {
		t.Fatalf("BackchannelTokenDeliveryMode(99).String() = %q, want empty", s)
	}
}

func TestParseBackchannelTokenDeliveryModeRejectsUnrecognized(t *testing.T) {
	// "push" is a real CIBA Core 1.0 value this package deliberately
	// doesn't implement (BackchannelTokenDeliveryMode's own doc
	// comment) — rejected the same as any other unrecognized string.
	for _, s := range []string{"", "PUSH", "push", "none"} {
		if _, err := ParseBackchannelTokenDeliveryMode(s); err == nil {
			t.Fatalf("ParseBackchannelTokenDeliveryMode(%q) = nil error, want error", s)
		}
	}
}
