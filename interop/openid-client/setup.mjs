// Writes this run's cmd/conformance-as configs and the harness's own
// client registry into the work directory the runner created.
//
//   node setup.mjs <work-dir>
//
// Every private_key_jwt client gets a fresh ES256 key pair, generated
// here; the mTLS clients' certificates come from the runner's openssl
// step (<work-dir>/certs). Nothing written here is committed: the work
// directory is a mktemp directory the runner deletes on exit.
import { generateKeyPairSync, X509Certificate, createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { ports, urls, SUBJECT } from './lib/env.mjs'

const workDir = process.argv[2]
if (!workDir) {
  throw new Error('usage: node setup.mjs <work-dir>')
}

function newSigningKey(kid) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const pub = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' }
  const priv = { ...privateKey.export({ format: 'jwk' }), kid, alg: 'ES256' }
  return { pub, priv }
}

// RFC 8705 §3.1 x5t#S256: base64url SHA-256 of the DER certificate.
function certificateThumbprint(certFile) {
  const der = new X509Certificate(readFileSync(certFile)).raw
  return createHash('sha256').update(der).digest('base64url')
}

const certs = join(workDir, 'certs')
const redirectURI = `${urls.harness}/cb`
const scopes = ['openid', 'offline_access', 'accounts']

// Aliases follow AGENTS.md's fapigo-{family}-{axis1}-{axis2} convention.
const clients = {}
const keyed = (id) => {
  const key = newSigningKey(`${id}-key1`)
  clients[id] = { id, privateJwk: key.priv }
  return { keys: [key.pub] }
}

const spPkjwtDpop = 'fapigo-sp-pkjwt-dpop'
const spMtlsMtls = 'fapigo-sp-mtls-mtls'
const spCcPkjwtDpop = 'fapigo-sp-cc-pkjwt-dpop'
const cibaPollPkjwt = 'fapigo-ciba-poll-pkjwt'
const cibaPingPkjwt = 'fapigo-ciba-ping-pkjwt'
const msPkjwtDpop = 'fapigo-ms-pkjwt-dpop'

const baseline = {
  listen_addr: `127.0.0.1:${ports.as}`,
  mtls_listen_addr: `127.0.0.1:${ports.asMTLS}`,
  issuer: urls.as,
  profile: 'fapi2-security',
  default_subject: SUBJECT,
  tls: { cert_file: join(certs, 'server.crt'), key_file: join(certs, 'server.key') },
  clients: [
    {
      id: spPkjwtDpop,
      redirect_uris: [redirectURI],
      client_assertion_algorithm: 'ES256',
      allowed_scopes: scopes,
      jwks: keyed(spPkjwtDpop),
    },
    {
      id: spMtlsMtls,
      redirect_uris: [redirectURI],
      client_auth_method: 'self_signed_tls_client_auth',
      expected_certificate_thumbprint: certificateThumbprint(join(certs, 'client-mtls.crt')),
      sender_constrain: 'mtls',
      allowed_scopes: scopes,
    },
    {
      id: spCcPkjwtDpop,
      redirect_uris: [redirectURI],
      client_assertion_algorithm: 'ES256',
      allowed_scopes: ['accounts'],
      allows_client_credentials_grant: true,
      jwks: keyed(spCcPkjwtDpop),
    },
    {
      id: cibaPollPkjwt,
      redirect_uris: [redirectURI],
      client_assertion_algorithm: 'ES256',
      backchannel_authentication_request_algorithm: 'ES256',
      sender_constrain: 'mtls',
      allowed_scopes: scopes,
      jwks: keyed(cibaPollPkjwt),
    },
    {
      id: cibaPingPkjwt,
      redirect_uris: [redirectURI],
      client_assertion_algorithm: 'ES256',
      backchannel_authentication_request_algorithm: 'ES256',
      sender_constrain: 'mtls',
      backchannel_token_delivery_mode: 'ping',
      backchannel_client_notification_endpoint: `${urls.harness}/ciba-notify`,
      allowed_scopes: scopes,
      jwks: keyed(cibaPingPkjwt),
    },
  ],
}

const messageSigning = {
  listen_addr: `127.0.0.1:${ports.asMessageSigning}`,
  issuer: urls.asMessageSigning,
  profile: 'fapi2-security-message-signing',
  default_subject: SUBJECT,
  tls: baseline.tls,
  clients: [
    {
      id: msPkjwtDpop,
      redirect_uris: [redirectURI],
      client_assertion_algorithm: 'ES256',
      request_object_algorithm: 'ES256',
      allowed_scopes: scopes,
      jwks: keyed(msPkjwtDpop),
    },
  ],
}

writeFileSync(join(workDir, 'as-baseline.json'), JSON.stringify(baseline, null, 2))
writeFileSync(join(workDir, 'as-message-signing.json'), JSON.stringify(messageSigning, null, 2))
writeFileSync(join(workDir, 'clients.json'), JSON.stringify({ redirectURI, clients }, null, 2), { mode: 0o600 })
console.log(`setup: wrote conformance-as configs and ${Object.keys(clients).length} client keys to ${workDir}`)
