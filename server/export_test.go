package server

// GrantEntryKey exposes grantEntryKey to the server_test package, so a
// test can write a GrantRegistry entry as the server would.
func GrantEntryKey(refreshTokenHash [32]byte) string { return grantEntryKey(refreshTokenHash) }
