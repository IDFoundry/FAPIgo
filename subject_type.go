package fapi

import "fmt"

// SubjectType is the kind of subject identifier ("sub") an end user has
// at a client (OpenID Connect Core 1.0 §8): the same identifier at every
// client, or one derived per sector so that clients can't correlate the
// user by it. Its zero value is no subject type at all: a server
// configuration refuses it, and a client registration reads it as
// "inherit the server's default".
type SubjectType uint8

const (
	_ SubjectType = iota

	// SubjectTypePublic gives an end user the same sub at every client
	// (OIDC Core §8, "public").
	SubjectTypePublic

	// SubjectTypePairwise gives an end user a different sub per sector,
	// so that clients in different sectors can't correlate the user by it
	// (OIDC Core §8.1, "pairwise").
	SubjectTypePairwise
)

// String returns the OpenID Connect wire value for t ("public" or
// "pairwise"), or "" if t is not a recognized subject type.
func (t SubjectType) String() string {
	switch t {
	case SubjectTypePublic:
		return "public"
	case SubjectTypePairwise:
		return "pairwise"
	default:
		return ""
	}
}

// IsValid reports whether t is SubjectTypePublic or SubjectTypePairwise.
func (t SubjectType) IsValid() bool {
	return t == SubjectTypePublic || t == SubjectTypePairwise
}

// ParseSubjectType maps an OpenID Connect subject_type value to a
// SubjectType. Only the exact, case-sensitive values "public" and
// "pairwise" are accepted.
func ParseSubjectType(value string) (SubjectType, error) {
	switch value {
	case "public":
		return SubjectTypePublic, nil
	case "pairwise":
		return SubjectTypePairwise, nil
	default:
		return 0, fmt.Errorf("fapi: unsupported subject type %q", value)
	}
}
