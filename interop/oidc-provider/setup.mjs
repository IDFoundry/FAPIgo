// Writes this run's oidc-provider client registrations and the Go
// driver's configuration into the work directory the runner created.
//
//   node setup.mjs <work-dir>
//
// Every private_key_jwt client gets a fresh ES256 key pair, generated
// here: the public half is registered with the provider, the private
// half goes to the driver as a PKCS #8 PEM file. The mTLS clients'
// certificates come from the runner's openssl step (<work-dir>/certs).
// Nothing written here is committed: the work directory is a mktemp
// directory the runner deletes on exit.
import { generateKeyPairSync, X509Certificate } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { ports, urls, ACCOUNT_ID, ACCOUNTS_RESOURCE, ACCOUNTS_SCOPE } from './lib/env.mjs'
import { workDirFromArgs } from './lib/workdir.mjs'

const workDir = workDirFromArgs('node setup.mjs <work-dir>')
const certs = join(workDir, 'certs')
const keysDir = join(workDir, 'keys')
mkdirSync(keysDir, { mode: 0o700 })

// Aliases follow AGENTS.md's fapigo-{family}-{axis1}-{axis2} convention.
const spPkjwtDpop = 'fapigo-sp-pkjwt-dpop'
const spMtlsMtls = 'fapigo-sp-mtls-mtls'
const msPkjwtDpop = 'fapigo-ms-pkjwt-dpop'
const spCcPkjwtDpop = 'fapigo-sp-cc-pkjwt-dpop'
const cibaPollPkjwt = 'fapigo-ciba-poll-pkjwt'
const cibaPingPkjwt = 'fapigo-ciba-ping-pkjwt'

// The redirect URI is never served: the driver stops following
// redirects when one reaches it and hands its query to the client.
const redirectURI = `${urls.driver}/cb`
const notificationEndpoint = `${urls.driver}/ciba-notify`
const cibaGrant = 'urn:openid:params:grant-type:ciba'

// signingKey writes a fresh ES256 private key for the driver and
// returns the client's JWKS for the provider.
function signingKey(clientId) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const file = join(keysDir, `${clientId}.key`)
  writeFileSync(file, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 })
  const kid = `${clientId}-key1`
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' }
  return { file, kid, jwks: { keys: [jwk] } }
}

// certificateJWKS registers a self-signed certificate for
// self_signed_tls_client_auth (RFC 8705 §2.2): the provider matches the
// presented certificate against the x5c of the registered keys.
function certificateJWKS(certFile) {
  const cert = new X509Certificate(readFileSync(certFile))
  const jwk = { ...cert.publicKey.export({ format: 'jwk' }), x5c: [cert.raw.toString('base64')] }
  return { keys: [jwk] }
}

const tls = (name) => ({ cert_file: join(certs, `${name}.crt`), key_file: join(certs, `${name}.key`) })

const codeDpopKey = signingKey(spPkjwtDpop)
const msKey = signingKey(msPkjwtDpop)
const ccKey = signingKey(spCcPkjwtDpop)
const cibaPollKey = signingKey(cibaPollPkjwt)
const cibaPingKey = signingKey(cibaPingPkjwt)

const codeClient = {
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  redirect_uris: [redirectURI],
  scope: 'openid offline_access',
}

const providerClients = [
  {
    ...codeClient,
    client_id: spPkjwtDpop,
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    dpop_bound_access_tokens: true,
    jwks: codeDpopKey.jwks,
  },
  {
    ...codeClient,
    client_id: spMtlsMtls,
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    tls_client_certificate_bound_access_tokens: true,
    jwks: certificateJWKS(join(certs, 'client-mtls.crt')),
  },
  {
    ...codeClient,
    client_id: msPkjwtDpop,
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    dpop_bound_access_tokens: true,
    require_signed_request_object: true,
    request_object_signing_alg: 'ES256',
    authorization_signed_response_alg: 'ES256',
    jwks: msKey.jwks,
  },
  {
    client_id: spCcPkjwtDpop,
    grant_types: ['client_credentials'],
    response_types: [],
    redirect_uris: [],
    scope: ACCOUNTS_SCOPE,
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    dpop_bound_access_tokens: true,
    jwks: ccKey.jwks,
  },
  ...[
    [cibaPollPkjwt, cibaPollKey, { backchannel_token_delivery_mode: 'poll' }],
    [cibaPingPkjwt, cibaPingKey, {
      backchannel_token_delivery_mode: 'ping',
      backchannel_client_notification_endpoint: notificationEndpoint,
    }],
  ].map(([clientId, key, delivery]) => ({
    client_id: clientId,
    grant_types: [cibaGrant],
    response_types: [],
    redirect_uris: [],
    scope: 'openid',
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    backchannel_authentication_request_signing_alg: 'ES256',
    // FAPI-CIBA's sender constraint is mTLS (see AGENTS.md).
    tls_client_certificate_bound_access_tokens: true,
    jwks: key.jwks,
    ...delivery,
  })),
]

// The driver's configuration: the issuer, the trust anchor for the
// provider's TLS certificate, and one entry per leg. Generic over the
// server: nothing here is specific to oidc-provider except the CIBA
// approval hook's URL.
const driver = {
  issuer: urls.op,
  ca_file: join(certs, 'ca.crt'),
  subject: ACCOUNT_ID,
  ciba_login_hint: ACCOUNT_ID,
  ciba_approval_url: `${urls.op}/harness/ciba-approve`,
  notification: {
    listen_addr: `127.0.0.1:${ports.driver}`,
    ...tls('server'),
  },
  legs: {
    'code-pkjwt-dpop': {
      client_id: spPkjwtDpop,
      redirect_uri: redirectURI,
      signing_key_file: codeDpopKey.file,
      signing_key_id: codeDpopKey.kid,
      scope: ['openid', 'offline_access'],
    },
    'code-mtls-mtls': {
      client_id: spMtlsMtls,
      redirect_uri: redirectURI,
      tls_client: tls('client-mtls'),
      scope: ['openid', 'offline_access'],
    },
    'message-signing': {
      client_id: msPkjwtDpop,
      redirect_uri: redirectURI,
      signing_key_file: msKey.file,
      signing_key_id: msKey.kid,
      scope: ['openid', 'offline_access'],
    },
    'client-credentials': {
      client_id: spCcPkjwtDpop,
      signing_key_file: ccKey.file,
      signing_key_id: ccKey.kid,
      scope: [ACCOUNTS_SCOPE],
      resource: [ACCOUNTS_RESOURCE],
    },
    'ciba-poll': {
      client_id: cibaPollPkjwt,
      signing_key_file: cibaPollKey.file,
      signing_key_id: cibaPollKey.kid,
      tls_client: tls('client-ciba'),
      scope: ['openid'],
    },
    'ciba-ping': {
      client_id: cibaPingPkjwt,
      signing_key_file: cibaPingKey.file,
      signing_key_id: cibaPingKey.kid,
      tls_client: tls('client-ciba'),
      scope: ['openid'],
    },
  },
}

writeFileSync(join(workDir, 'op-clients.json'), JSON.stringify(providerClients, null, 2))
writeFileSync(join(workDir, 'driver.json'), JSON.stringify(driver, null, 2))
console.log(`setup: wrote ${providerClients.length} client registrations and the driver configuration to ${workDir}`)
