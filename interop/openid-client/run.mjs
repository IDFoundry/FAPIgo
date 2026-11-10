// The interop legs, each a named node:test case reporting pass/fail on
// its own. The runner (interop/run-openid-client.sh) has already
// started conformance-as and written this run's configuration.
//
//   node --test-reporter=spec run.mjs <work-dir>
import { test } from 'node:test'

import { loadRun } from './lib/harness.mjs'
import { workDirFromArgs } from './lib/workdir.mjs'
import authorizationCodeDPoP from './legs/authorization-code-dpop.mjs'
import authorizationCodeMTLS from './legs/authorization-code-mtls.mjs'
import messageSigning from './legs/message-signing.mjs'
import clientCredentials from './legs/client-credentials.mjs'
import cibaPoll from './legs/ciba-poll.mjs'
import cibaPing from './legs/ciba-ping.mjs'

const run = loadRun(workDirFromArgs('node run.mjs <work-dir>'))

const legs = [
  ['1 authorization code + PAR + PKCE + private_key_jwt + DPoP, UserInfo, resource, refresh', authorizationCodeDPoP],
  ['2 authorization code + self_signed_tls_client_auth + certificate-bound tokens (mTLS aliases)', authorizationCodeMTLS],
  ['3 message signing: JAR via PAR + JARM + private_key_jwt + DPoP', messageSigning],
  ['4 client_credentials + private_key_jwt + DPoP, resource', clientCredentials],
  ['5 CIBA poll + private_key_jwt + certificate-bound tokens', cibaPoll],
  ['6 CIBA ping + private_key_jwt + certificate-bound tokens', cibaPing],
]

for (const [name, leg] of legs) {
  test(name, { timeout: 60_000 }, () => leg(run))
}
