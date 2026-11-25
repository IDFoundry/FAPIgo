package server

// GrantEntryKey exposes grantEntryKey to the server_test package, so a
// test can write a GrantRegistry entry as the server would.
func GrantEntryKey(refreshTokenHash [32]byte) string { return grantEntryKey(refreshTokenHash) }

// MaxFormParameters exposes maxFormParameters to the server_test
// package, so a test can hold FormRequestFromHTTP to the bound itself.
const MaxFormParameters = maxFormParameters

// RefreshTokenHash exposes refreshTokenHash to the server_test package:
// the digest a server of issuer stores refreshToken under.
func RefreshTokenHash(issuer, refreshToken string) [32]byte {
	return refreshTokenHash(issuer, refreshToken)
}

// AuthorizationCodeHash exposes authorizationCodeHash to the
// server_test package for a code issued to a client that didn't
// authenticate by Client Attestation, bound to no DPoP key: the digest
// the server stores it under, from which a test names its grant.
func AuthorizationCodeHash(issuer, code, codeChallenge, redirectURI string) [32]byte {
	return authorizationCodeHash(issuer, code, codeBinding{codeChallenge: codeChallenge, redirectURI: redirectURI})
}
