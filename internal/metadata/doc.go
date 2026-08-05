// Package metadata implements shared parsing and validation for
// authorization-server and client metadata documents (OAuth 2.0
// Authorization Server Metadata / OpenID Connect Discovery, and OAuth 2.0
// Dynamic Client Registration metadata).
//
// client uses this when consuming AS discovery documents; server uses it
// when producing its own metadata document and when validating registered
// client metadata. The parsing and shape validation is identical on both
// sides; what each role does with a given field (trust it vs. assert it)
// is not, and stays in the respective public package.
package metadata
