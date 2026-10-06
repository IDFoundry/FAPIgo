# resource vectors

Reserved for resource-server verification test vectors; it holds none
today. The OIDF suite has no resource-server plan, so that role's
verification is covered by the `resource` package's own tests instead:

- [`resource/verify_test.go`](../../../resource/verify_test.go) — valid
  and invalid DPoP proofs, replay, a method (`htm`) mismatch, a proof
  signed by a key other than the token's `cnf.jkt`, malformed and
  repeated `Authorization` headers, revoked and expired tokens, opaque
  tokens.
- [`resource/mtls_test.go`](../../../resource/mtls_test.go) — mTLS-bound
  tokens (`cnf.x5t#S256`): the right certificate, the wrong one, none,
  and a token presented under the other binding's scheme.
- [`resource/verify_fuzz_test.go`](../../../resource/verify_fuzz_test.go)
  and `internal/dpop`'s own tests and fuzz targets, for the DPoP proof
  parsing and claim checks underneath.

The AS-side suite plans also call a real protected resource with the
tokens they're issued (see [`../../README.md`](../../README.md)), which
exercises the same `resource.Verifier` end to end.
