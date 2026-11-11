// Configures the running Keycloak for this interop run through its
// admin REST API, and writes the Go driver's configuration into the work
// directory the runner created.
//
//   node setup.mjs <work-dir>
//
// Needs Node.js only (no npm packages). The runner exports the bootstrap
// administrator's credentials (KC_BOOTSTRAP_ADMIN_USERNAME and
// KC_BOOTSTRAP_ADMIN_PASSWORD) and NODE_EXTRA_CA_CERTS for the run's
// test CA.
//
// The realm is built in the order an administrator would: realm settings
// and the test user, an ES256 signing key, the clients, and the client
// policies that put each client under Keycloak's own FAPI 2.0 client
// profiles, whose executors then check (and, where they auto-configure,
// adjust) every client. Every
// private_key_jwt client gets a fresh ES256 key pair, generated here:
// the public half is registered with Keycloak, the private half goes to
// the driver as a PKCS #8 PEM file. Nothing written here is committed:
// the work directory is a mktemp directory the runner deletes on exit.
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { workDirFromArgs } from '../oidc-provider/lib/workdir.mjs'
import { hostAddr, ports, urls, ACCOUNTS_SCOPE, REALM, USERNAME } from './lib/env.mjs'

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
const password = randomBytes(18).toString('base64url')

// --- the admin REST API ---------------------------------------------------

async function adminToken() {
  const res = await fetch(`${urls.keycloak}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: process.env.KC_BOOTSTRAP_ADMIN_USERNAME,
      password: process.env.KC_BOOTSTRAP_ADMIN_PASSWORD,
    }),
  })
  if (!res.ok) {
    throw new Error(`admin token: ${res.status} ${await res.text()}`)
  }
  return (await res.json()).access_token
}

const token = await adminToken()

async function admin(method, path, body) {
  const res = await fetch(`${urls.keycloak}/admin/realms${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) {
    throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`)
  }
  const text = await res.text()
  return text ? JSON.parse(text) : undefined
}

// --- the realm ------------------------------------------------------------

await admin('POST', '', {
  realm: REALM,
  enabled: true,
  defaultSignatureAlgorithm: 'ES256',
  // CIBA: poll by default (a ping client says so itself), login_hint is
  // the username, a one-minute request lifetime (the driver's limit) and
  // a one-second polling interval to keep the run short.
  attributes: {
    cibaBackchannelTokenDeliveryMode: 'poll',
    cibaExpiresIn: '60',
    cibaInterval: '1',
    cibaAuthRequestedUserHint: 'login_hint',
  },
  users: [{
    username: USERNAME,
    enabled: true,
    email: `${USERNAME}@example.com`,
    emailVerified: true,
    firstName: 'Interop',
    lastName: 'User',
    credentials: [{ type: 'password', value: password, temporary: false }],
  }],
})

// ES256 for ID tokens, access tokens and JARM responses, preferred over
// the realm's default RSA key.
await admin('POST', `/${REALM}/components`, {
  name: 'interop-es256',
  providerId: 'ecdsa-generated',
  providerType: 'org.keycloak.keys.KeyProvider',
  config: { priority: ['200'], ecdsaEllipticCurveKey: ['P-256'] },
})

// The scope the client_credentials client asks for.
await admin('POST', `/${REALM}/client-scopes`, {
  name: ACCOUNTS_SCOPE,
  protocol: 'openid-connect',
  attributes: { 'include.in.token.scope': 'true', 'display.on.consent.screen': 'false' },
})

// Each client carries an interop.profile attribute naming the client
// policy (below) it falls under.
const profileAttribute = 'interop.profile'

// --- the clients ----------------------------------------------------------

// signingKey writes a fresh ES256 private key for the driver and
// returns the client's JWKS for Keycloak.
function signingKey(clientId) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const file = join(keysDir, `${clientId}.key`)
  writeFileSync(file, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 })
  const kid = `${clientId}-key1`
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' }
  return { file, kid, jwks: { keys: [jwk] } }
}

const tls = (name) => ({ cert_file: join(certs, `${name}.crt`), key_file: join(certs, `${name}.key`) })

const codeDpopKey = signingKey(spPkjwtDpop)
const msKey = signingKey(msPkjwtDpop)
const ccKey = signingKey(spCcPkjwtDpop)
const cibaPollKey = signingKey(cibaPollPkjwt)
const cibaPingKey = signingKey(cibaPingPkjwt)

const base = (clientId, profile) => ({
  clientId,
  protocol: 'openid-connect',
  publicClient: false,
  standardFlowEnabled: false,
  implicitFlowEnabled: false,
  directAccessGrantsEnabled: false,
  serviceAccountsEnabled: false,
  attributes: {
    [profileAttribute]: profile,
    // ES256 throughout. The FAPI 2.0 profiles' secure-signature-algorithm
    // executor fills in any of these left unset with PS256, and makes
    // UserInfo responses signed.
    'id.token.signed.response.alg': 'ES256',
    'access.token.signed.response.alg': 'ES256',
    'user.info.response.signature.alg': 'ES256',
    'request.object.signature.alg': 'ES256',
  },
})

const privateKeyJWT = (key) => ({
  clientAuthenticatorType: 'client-jwt',
  attributes: {
    'use.jwks.string': 'true',
    'jwks.string': JSON.stringify(key.jwks),
    'token.endpoint.auth.signing.alg': 'ES256',
  },
})

const codeFlow = {
  standardFlowEnabled: true,
  redirectUris: [redirectURI],
  attributes: {
    'pkce.code.challenge.method': 'S256',
    'require.pushed.authorization.requests': 'true',
  },
}

// merge combines client fragments, merging their attributes.
function merge(...parts) {
  const out = {}
  for (const part of parts) {
    Object.assign(out, part, { attributes: { ...out.attributes, ...part.attributes } })
  }
  return out
}

const certificateBound = { attributes: { 'tls.client.certificate.bound.access.tokens': 'true' } }
const dpopBound = { attributes: { 'dpop.bound.access.tokens': 'true' } }

const cibaClient = (clientId, key, delivery) => merge(
  base(clientId, 'fapi2-ciba'),
  privateKeyJWT(key),
  certificateBound,
  {
    attributes: {
      'oidc.ciba.grant.enabled': 'true',
      'ciba.backchannel.auth.request.signing.alg': 'ES256',
      ...delivery,
    },
  },
)

const clients = [
  merge(base(spPkjwtDpop, 'fapi2-dpop'), privateKeyJWT(codeDpopKey), codeFlow, dpopBound),
  // Keycloak's X.509 client authenticator is RFC 8705 §2.1's PKI method
  // (tls_client_auth): the certificate chains to the run's test CA (the
  // server's trust store) and its subject DN is registered.
  merge(base(spMtlsMtls, 'fapi2-mtls'), codeFlow, certificateBound, {
    clientAuthenticatorType: 'client-x509',
    attributes: { 'x509.subjectdn': 'CN=client-mtls', 'x509.allow.regex.pattern.comparison': 'false' },
  }),
  merge(base(msPkjwtDpop, 'fapi2-ms-dpop'), privateKeyJWT(msKey), codeFlow, dpopBound, {
    attributes: {
      'request.object.signature.alg': 'ES256',
      'request.object.required': 'request or request_uri',
      'authorization.signed.response.alg': 'ES256',
    },
  }),
  merge(base(spCcPkjwtDpop, 'fapi2-dpop'), privateKeyJWT(ccKey), dpopBound, {
    serviceAccountsEnabled: true,
    // Only the scope the leg asks for, so the token response's scope is
    // exactly that.
    defaultClientScopes: [],
    optionalClientScopes: [ACCOUNTS_SCOPE],
  }),
  cibaClient(cibaPollPkjwt, cibaPollKey, { 'ciba.backchannel.token.delivery.mode': 'poll' }),
  cibaClient(cibaPingPkjwt, cibaPingKey, {
    'ciba.backchannel.token.delivery.mode': 'ping',
    'ciba.backchannel.client.notification.endpoint': `${urls.driverFromKeycloak}/ciba-notify`,
  }),
]

await Promise.all(clients.map((client) => admin('POST', `/${REALM}/clients`, client)))

// The client policies, one per kind of client, each applying Keycloak's
// own global FAPI 2.0 client profiles to the clients whose
// interop.profile attribute names it. Keycloak evaluates a policy's
// conditions against a client that exists, so the policies are set
// after the clients are created, and each client is then saved again:
// that update runs the profiles' executors over it, which refuse a
// client the profile doesn't allow and auto-configure the rest
// (consent required, full scope disabled).
const policy = (name, profiles) => ({
  name,
  enabled: true,
  conditions: [{
    condition: 'client-attributes',
    // The condition takes its attributes as a JSON-encoded list.
    configuration: { 'is-negative-logic': false, attributes: JSON.stringify([{ key: profileAttribute, value: name }]) },
  }],
  profiles,
})
await admin('PUT', `/${REALM}/client-policies/policies`, {
  policies: [
    policy('fapi2-dpop', ['fapi-2-dpop-security-profile']),
    policy('fapi2-mtls', ['fapi-2-security-profile']),
    policy('fapi2-ms-dpop', ['fapi-2-dpop-message-signing']),
    policy('fapi2-ciba', ['fapi-2-security-profile', 'fapi-ciba']),
  ],
})

async function saveUnderPolicy({ clientId }) {
  const [registered] = await admin('GET', `/${REALM}/clients?clientId=${clientId}`)
  await admin('PUT', `/${REALM}/clients/${registered.id}`, registered)
  const [updated] = await admin('GET', `/${REALM}/clients?clientId=${clientId}`)
  // full-scope-disabled is in every FAPI 2.0 profile: proof the policy
  // matched this client.
  if (updated.fullScopeAllowed !== false) {
    throw new Error(`${clientId}: no FAPI 2.0 client policy applied`)
  }
}
await Promise.all(clients.map(saveUnderPolicy))

// The test user's sub is the ID Keycloak gave it.
const [user] = await admin('GET', `/${REALM}/users?exact=true&username=${USERNAME}`)

// --- the driver's configuration ---------------------------------------------

// Generic over the server: the issuer, the trust anchor for its TLS
// certificate, the test user, the harness's CIBA approval hook, the
// login form's fields, and one entry per leg.
const driver = {
  issuer: urls.issuer,
  ca_file: join(certs, 'ca.crt'),
  subject: user.id,
  ciba_login_hint: USERNAME,
  ciba_approval_url: `${urls.harness}/approve`,
  // Keycloak's login page, and its consent page should one appear
  // (the FAPI 2.0 profiles set consent required on each client they
  // register): accept is the consent form's submit button.
  login_form: { username: USERNAME, password, accept: 'Yes' },
  notification: {
    listen_addr: `${hostAddr}:${ports.driver}`,
    ...tls('server'),
  },
  legs: {
    'code-pkjwt-dpop': {
      client_id: spPkjwtDpop,
      redirect_uri: redirectURI,
      signing_key_file: codeDpopKey.file,
      signing_key_id: codeDpopKey.kid,
      id_token_signed_response_alg: 'ES256',
      userinfo_signed_response_alg: 'ES256',
      scope: ['openid'],
    },
    'code-mtls-mtls': {
      client_id: spMtlsMtls,
      redirect_uri: redirectURI,
      tls_client: tls('client-mtls'),
      tls_client_auth: 'tls_client_auth',
      id_token_signed_response_alg: 'ES256',
      userinfo_signed_response_alg: 'ES256',
      scope: ['openid'],
    },
    'message-signing': {
      client_id: msPkjwtDpop,
      redirect_uri: redirectURI,
      signing_key_file: msKey.file,
      signing_key_id: msKey.kid,
      id_token_signed_response_alg: 'ES256',
      userinfo_signed_response_alg: 'ES256',
      scope: ['openid'],
    },
    'client-credentials': {
      client_id: spCcPkjwtDpop,
      signing_key_file: ccKey.file,
      signing_key_id: ccKey.kid,
      scope: [ACCOUNTS_SCOPE],
    },
    'ciba-poll': {
      client_id: cibaPollPkjwt,
      signing_key_file: cibaPollKey.file,
      signing_key_id: cibaPollKey.kid,
      tls_client: tls('client-ciba'),
      id_token_signed_response_alg: 'ES256',
      userinfo_signed_response_alg: 'ES256',
      scope: ['openid'],
    },
    'ciba-ping': {
      client_id: cibaPingPkjwt,
      signing_key_file: cibaPingKey.file,
      signing_key_id: cibaPingKey.kid,
      tls_client: tls('client-ciba'),
      id_token_signed_response_alg: 'ES256',
      userinfo_signed_response_alg: 'ES256',
      scope: ['openid'],
    },
  },
}

writeFileSync(join(workDir, 'driver.json'), JSON.stringify(driver, null, 2), { mode: 0o600 })
console.log(`setup: configured realm ${REALM} with ${clients.length} clients and wrote the driver configuration to ${workDir}`)
