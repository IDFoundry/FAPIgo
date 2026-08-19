# Security Policy

FAPIgo implements FAPI 2.0 — protocol code intended to run in
financial-grade, security-critical deployments. If you believe you've
found a vulnerability (a protocol violation, a cryptographic weakness,
an authentication/authorization bypass, or anything else with security
impact), please report it privately rather than opening a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security**
tab on this repository and select **Report a vulnerability**. This
creates a private advisory visible only to maintainers until a fix is
ready, rather than a public issue.

If private reporting isn't available for any reason, open a regular
issue asking a maintainer to open a private channel — please don't
include vulnerability details in a public issue.

## Supported versions

FAPIgo is under active development (see the README's work-in-progress
notice) and does not yet have tagged releases. Reports against `main`
are the ones we can act on.

## What to include

- The affected package/file and, if possible, a minimal reproduction.
- The specific FAPI 2.0 / OAuth 2.0 / OIDC requirement or security
  property you believe is violated (a spec section reference helps).
- Whether the issue is exploitable against a default configuration or
  requires a specific, non-default setup.

## Response

We'll acknowledge reports and work with you on a fix and coordinated
disclosure timeline before any public advisory is published.
