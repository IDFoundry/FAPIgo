# Conformance

Conformance testing is tracked separately per role: passing the
authorization-server suite says nothing about client conformance, even
where both sides use the same internal JOSE code, because the protocol
behaviour and negative-test expectations differ. See
[ARCHITECTURE.md](../ARCHITECTURE.md#conformance-strategy).

- `client/` — OpenID Foundation RP/client conformance configuration and
  run scripts.
- `server/` — OpenID Foundation FAPI 2.0 AS conformance configuration and
  run scripts.
- `resource/` — resource-server verification test vectors (DPoP proof
  validation, access-token binding checks) used outside the OIDF suite,
  which does not cover the resource-server role.
