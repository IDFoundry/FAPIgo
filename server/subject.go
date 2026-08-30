package server

import (
	"fmt"
	"time"
)

// SubjectID identifies a resource owner the server has authenticated. It
// has no public zero-value use — construct one with NewSubjectID — so a
// caller can't accidentally treat an empty string as a valid subject.
type SubjectID struct {
	value string
}

// NewSubjectID validates and wraps value.
func NewSubjectID(value string) (SubjectID, error) {
	if value == "" {
		return SubjectID{}, fmt.Errorf("server: subject ID is empty")
	}
	return SubjectID{value: value}, nil
}

// String returns the subject's wire value.
func (s SubjectID) String() string { return s.value }

// AuthenticatedSubject is a resource owner the embedding application has
// verified. It can only be constructed via NewAuthenticatedSubject, so
// CompleteAuthorization never receives an authorization result asserting
// authentication happened without that assertion having gone through
// validation.
type AuthenticatedSubject struct {
	id SubjectID
}

// NewAuthenticatedSubject wraps id.
func NewAuthenticatedSubject(id SubjectID) (AuthenticatedSubject, error) {
	if id.value == "" {
		return AuthenticatedSubject{}, fmt.Errorf("server: authenticated subject requires a non-zero SubjectID")
	}
	return AuthenticatedSubject{id: id}, nil
}

// ID returns the authenticated subject's ID.
func (a AuthenticatedSubject) ID() SubjectID { return a.id }

// AuthenticationContext describes how and when the resource owner
// authenticated.
type AuthenticationContext struct {
	authTime time.Time
	acr      string
	amr      []string
}

// NewAuthenticationContext validates and wraps its arguments. acr and
// amr are optional (pass "" / nil if the application doesn't track
// them); authTime is required.
func NewAuthenticationContext(authTime time.Time, acr string, amr []string) (AuthenticationContext, error) {
	if authTime.IsZero() {
		return AuthenticationContext{}, fmt.Errorf("server: authentication context requires a non-zero authTime")
	}
	amrCopy := make([]string, len(amr))
	copy(amrCopy, amr)
	return AuthenticationContext{authTime: authTime, acr: acr, amr: amrCopy}, nil
}

// GrantedAuthorization is what the embedding application decided to
// approve — which may be a subset of what was originally requested.
// CompleteAuthorization rejects a scope not present in the original
// request; it does not otherwise second-guess this decision.
type GrantedAuthorization struct {
	Scope []string
}
