package storage

import "fmt"

// String returns the canonical wire value for c — the same value a
// config-driven deployment would read from a client_auth_method (RFC
// 8705 §2.1's registered token_endpoint_auth_method values, plus this
// package's own tls_client_auth_san_* names for which certificate field
// ClientAuthMethodTLSClientAuth's four SAN siblings match, matching
// each constant's own doc comment) field — or "" if c is not one of
// this package's recognized values.
func (c ClientAuthMethod) String() string {
	switch c {
	case ClientAuthMethodPrivateKeyJWT:
		return "private_key_jwt"
	case ClientAuthMethodSelfSignedTLSClientAuth:
		return "self_signed_tls_client_auth"
	case ClientAuthMethodTLSClientAuth:
		return "tls_client_auth"
	case ClientAuthMethodTLSClientAuthSANDNS:
		return "tls_client_auth_san_dns"
	case ClientAuthMethodTLSClientAuthSANURI:
		return "tls_client_auth_san_uri"
	case ClientAuthMethodTLSClientAuthSANIP:
		return "tls_client_auth_san_ip"
	case ClientAuthMethodTLSClientAuthSANEmail:
		return "tls_client_auth_san_email"
	default:
		return ""
	}
}

// IsValid reports whether c is one of this package's recognized
// ClientAuthMethod values — every declared constant, including the
// zero value ClientAuthMethodPrivateKeyJWT, which (unlike fapi's
// algorithm enums) is a real, meaningful default rather than a
// reserved invalid marker.
func (c ClientAuthMethod) IsValid() bool {
	switch c {
	case ClientAuthMethodPrivateKeyJWT, ClientAuthMethodSelfSignedTLSClientAuth, ClientAuthMethodTLSClientAuth,
		ClientAuthMethodTLSClientAuthSANDNS, ClientAuthMethodTLSClientAuthSANURI,
		ClientAuthMethodTLSClientAuthSANIP, ClientAuthMethodTLSClientAuthSANEmail:
		return true
	default:
		return false
	}
}

// ParseClientAuthMethod maps a wire value (see String) to its
// ClientAuthMethod. It rejects every string outside this package's own
// closed set, including "" — a caller whose own config format treats an
// absent field as the default (ClientAuthMethodPrivateKeyJWT) makes
// that policy decision itself before calling Parse, the same way an
// absent JOSE "alg" header is a caller decision, not
// ParseSignatureAlgorithm's.
func ParseClientAuthMethod(s string) (ClientAuthMethod, error) {
	switch s {
	case "private_key_jwt":
		return ClientAuthMethodPrivateKeyJWT, nil
	case "self_signed_tls_client_auth":
		return ClientAuthMethodSelfSignedTLSClientAuth, nil
	case "tls_client_auth":
		return ClientAuthMethodTLSClientAuth, nil
	case "tls_client_auth_san_dns":
		return ClientAuthMethodTLSClientAuthSANDNS, nil
	case "tls_client_auth_san_uri":
		return ClientAuthMethodTLSClientAuthSANURI, nil
	case "tls_client_auth_san_ip":
		return ClientAuthMethodTLSClientAuthSANIP, nil
	case "tls_client_auth_san_email":
		return ClientAuthMethodTLSClientAuthSANEmail, nil
	default:
		return 0, fmt.Errorf("storage: unrecognized client auth method %q", s)
	}
}

// String returns the canonical wire value for s ("dpop" or "mtls"), the
// same value a config-driven deployment would read from a
// sender_constrain field — or "" if s is not one of this package's
// recognized values.
func (s SenderConstrain) String() string {
	switch s {
	case SenderConstrainDPoP:
		return "dpop"
	case SenderConstrainMTLS:
		return "mtls"
	default:
		return ""
	}
}

// IsValid reports whether s is one of this package's recognized
// SenderConstrain values — both declared constants, including the zero
// value SenderConstrainDPoP, which is a real, meaningful default rather
// than a reserved invalid marker.
func (s SenderConstrain) IsValid() bool {
	switch s {
	case SenderConstrainDPoP, SenderConstrainMTLS:
		return true
	default:
		return false
	}
}

// ParseSenderConstrain maps a wire value (see String) to its
// SenderConstrain. It rejects every string outside this package's own
// closed set, including "" — see ParseClientAuthMethod's own doc
// comment for why an absent-field default is a caller decision, not
// Parse's.
func ParseSenderConstrain(s string) (SenderConstrain, error) {
	switch s {
	case "dpop":
		return SenderConstrainDPoP, nil
	case "mtls":
		return SenderConstrainMTLS, nil
	default:
		return 0, fmt.Errorf("storage: unrecognized sender constrain %q", s)
	}
}

// String returns the canonical wire value for m — CIBA Core 1.0's own
// backchannel_token_delivery_mode client metadata values ("poll" or
// "ping"; "push" is a third registered value this package does not
// implement, per BackchannelTokenDeliveryMode's own doc comment) — or
// "" if m is not one of this package's recognized values.
func (m BackchannelTokenDeliveryMode) String() string {
	switch m {
	case BackchannelTokenDeliveryModePoll:
		return "poll"
	case BackchannelTokenDeliveryModePing:
		return "ping"
	default:
		return ""
	}
}

// IsValid reports whether m is one of this package's recognized
// BackchannelTokenDeliveryMode values — both declared constants,
// including the zero value BackchannelTokenDeliveryModePoll, which is a
// real, meaningful default rather than a reserved invalid marker.
func (m BackchannelTokenDeliveryMode) IsValid() bool {
	switch m {
	case BackchannelTokenDeliveryModePoll, BackchannelTokenDeliveryModePing:
		return true
	default:
		return false
	}
}

// ParseBackchannelTokenDeliveryMode maps a wire value (see String) to
// its BackchannelTokenDeliveryMode. It rejects every string outside
// this package's own closed set, including "" and "push" — see
// ParseClientAuthMethod's own doc comment for why an absent-field
// default is a caller decision, not Parse's; "push" is rejected because
// this package doesn't implement it, not because it's an unrecognized
// CIBA value.
func ParseBackchannelTokenDeliveryMode(s string) (BackchannelTokenDeliveryMode, error) {
	switch s {
	case "poll":
		return BackchannelTokenDeliveryModePoll, nil
	case "ping":
		return BackchannelTokenDeliveryModePing, nil
	default:
		return 0, fmt.Errorf("storage: unrecognized backchannel token delivery mode %q", s)
	}
}
