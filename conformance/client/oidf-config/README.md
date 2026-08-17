# client oidf-config

Empty, and — unlike [`../../server/oidf-config`](../../server/oidf-config)
— expected to stay that way for `cmd/conformance-client` as it exists
today.

The server-side driver needs files here because it's a long-running AS
that a separately-launched suite plan config must know the registered
`client_id`(s), redirect URI, and public JWKS for ahead of time. The
client-side driver is the opposite shape: it's a single short-lived
process that plays the RP itself, so it generates its own throwaway
ES256 keypair, alias, and plan config in-process for every run (see
[`../scripts/README.md`](../scripts/README.md)) — there's no
externally-defined suite plan for a config file here to describe.

If a future client test plan needs configuration this driver can't
express by building the plan JSON directly in Go (RS256 keys, a second
registered client, ...), that's the point to reconsider this directory,
not before.
