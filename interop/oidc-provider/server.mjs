// Starts oidc-provider as a FAPI 2.0 authorization server for the
// interop run, over HTTPS with the run's test CA:
//
//   node server.mjs <work-dir>
//
// Two listeners serve the same provider: the issuer's own port, and an
// mTLS port that requires a client certificate and is advertised as
// mtls_endpoint_aliases (RFC 8705 §5). The issuer's port also serves
// the interaction routes, which sign the one test user in and consent
// to what was asked for without a page, and the CIBA approval hook the
// driver calls in place of an authentication device. Both are test
// fixtures: nothing here authenticates anyone.
import { randomBytes, generateKeyPairSync, X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:https'
import { join } from 'node:path'

import Provider, { errors } from 'oidc-provider'

import { ports, urls, ACCOUNT_ID, ACCOUNTS_RESOURCE, ACCOUNTS_SCOPE } from './lib/env.mjs'
import { workDirFromArgs } from './lib/workdir.mjs'

const workDir = workDirFromArgs('node server.mjs <work-dir>')
const certs = join(workDir, 'certs')
const clients = JSON.parse(readFileSync(join(workDir, 'op-clients.json'), 'utf8'))

// The provider's own signing key: ES256 for ID tokens, JARM responses
// and everything else it signs.
const signingKey = {
  ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }),
  kid: 'op-es256',
  alg: 'ES256',
  use: 'sig',
}

const algorithms = ['ES256', 'PS256']

// The certificate the client presented on this connection, if any. Only
// the mTLS listener requires one.
function peerCertificate(ctx) {
  const peer = ctx.socket.getPeerCertificate?.()
  if (!peer?.raw) {
    return undefined
  }
  return new X509Certificate(peer.raw)
}

const provider = new Provider(urls.op, {
  clients,
  jwks: { keys: [signingKey] },
  cookies: { keys: [randomBytes(32).toString('base64url')] },
  scopes: ['openid', 'offline_access', ACCOUNTS_SCOPE],
  claims: { openid: ['sub'] },
  async findAccount(_ctx, id) {
    if (id !== ACCOUNT_ID) {
      return undefined
    }
    return { accountId: id, claims: () => ({ sub: id }) }
  },
  // oidc-provider's own fetch refuses loopback addresses (SSRF
  // protection); lift that for the driver's CIBA notification endpoint
  // alone, which this run serves on localhost.
  fetch(url, options) {
    if (new URL(url).origin === urls.driver) {
      delete options.dispatcher
    }
    return globalThis.fetch(url, options)
  },
  clientAuthMethods: ['private_key_jwt', 'self_signed_tls_client_auth'],
  clientDefaults: {
    id_token_signed_response_alg: 'ES256',
    authorization_signed_response_alg: 'ES256',
  },
  enabledJWA: {
    authorizationSigningAlgValues: algorithms,
    clientAuthSigningAlgValues: algorithms,
    dPoPSigningAlgValues: algorithms,
    idTokenSigningAlgValues: ['ES256'],
    requestObjectSigningAlgValues: algorithms,
    userinfoSigningAlgValues: algorithms,
  },
  discovery: {
    mtls_endpoint_aliases: {
      token_endpoint: `${urls.opMTLS}/token`,
      pushed_authorization_request_endpoint: `${urls.opMTLS}/request`,
      userinfo_endpoint: `${urls.opMTLS}/me`,
      backchannel_authentication_endpoint: `${urls.opMTLS}/backchannel`,
    },
  },
  features: {
    devInteractions: { enabled: false },
    fapi: { enabled: true, profile: '2.0' },
    pushedAuthorizationRequests: { enabled: true, requirePushedAuthorizationRequests: true },
    dPoP: { enabled: true, nonceSecret: randomBytes(32), requireNonce: () => true },
    mTLS: {
      enabled: true,
      certificateBoundAccessTokens: true,
      selfSignedTlsClientAuth: true,
      getCertificate: peerCertificate,
    },
    requestObjects: { enabled: true },
    jwtResponseModes: { enabled: true },
    clientCredentials: { enabled: true },
    resourceIndicators: {
      enabled: true,
      async getResourceServerInfo(_ctx, resourceIndicator) {
        if (resourceIndicator !== ACCOUNTS_RESOURCE) {
          throw new errors.InvalidTarget()
        }
        return { scope: ACCOUNTS_SCOPE, accessTokenFormat: 'opaque' }
      },
    },
    ciba: {
      enabled: true,
      deliveryModes: ['poll', 'ping'],
      async processLoginHint(_ctx, loginHint) {
        return loginHint === ACCOUNT_ID ? ACCOUNT_ID : undefined
      },
      async processLoginHintToken() {
        throw new errors.InvalidRequest('login_hint_token is not supported')
      },
      async validateRequestContext() {
        // No request_context policy.
      },
      async verifyUserCode() {
        // No user_code policy.
      },
      async triggerAuthenticationDevice() {
        // The driver approves through /harness/ciba-approve instead.
      },
    },
  },
})

provider.on('server_error', (_ctx, err) => console.error('server_error', err))
for (const event of ['authorization.error', 'grant.error', 'pushed_authorization_request.error',
  'backchannel_authentication.error', 'userinfo.error', 'backchannel.error']) {
  provider.on(event, (_ctx, err) => console.error(event, err.message, err.error_description ?? '', err.error_detail ?? '', err.cause?.message ?? ''))
}

// Grants what the interaction asks for: the requested OIDC scopes and
// claims, and the scopes of any requested resource server.
async function consent(details) {
  const { prompt, params, session, grantId } = details
  const grant = grantId
    ? await provider.Grant.find(grantId)
    : new provider.Grant({ accountId: session.accountId, clientId: params.client_id })
  const missing = prompt.details
  if (missing.missingOIDCScope) {
    grant.addOIDCScope(missing.missingOIDCScope.join(' '))
  }
  if (missing.missingOIDCClaims) {
    grant.addOIDCClaims(missing.missingOIDCClaims)
  }
  for (const [indicator, scopes] of Object.entries(missing.missingResourceScopes ?? {})) {
    grant.addResourceScope(indicator, scopes.join(' '))
  }
  return { consent: { grantId: await grant.save() } }
}

// GET /interaction/:uid resolves whichever prompt the provider raised
// (login, then consent) and redirects back to the provider.
async function interaction(req, res) {
  const details = await provider.interactionDetails(req, res)
  let result
  switch (details.prompt.name) {
    case 'login':
      result = { login: { accountId: ACCOUNT_ID } }
      break
    case 'consent':
      result = await consent(details)
      break
    default:
      result = { error: 'access_denied', error_description: `unhandled prompt ${details.prompt.name}` }
  }
  await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true })
}

async function readForm(req) {
  const chunks = []
  for await (const chunk of req) {
    chunks.push(chunk)
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
}

// POST /harness/ciba-approve (form: auth_req_id) approves a pending
// CIBA request for the test user, as an authentication device would:
// a grant for the requested scope and claims, then
// provider.backchannelResult, which also sends a ping-mode client its
// notification.
async function approveBackchannel(req, res) {
  const authReqID = (await readForm(req)).get('auth_req_id')
  const request = authReqID && await provider.BackchannelAuthenticationRequest.find(authReqID)
  if (!request) {
    res.writeHead(404).end('unknown auth_req_id\n')
    return
  }
  const grant = new provider.Grant({ accountId: request.accountId, clientId: request.clientId })
  grant.addOIDCScope(request.scope)
  if (request.claims) {
    grant.addOIDCClaims(Object.keys(request.claims.id_token ?? {}))
  }
  await grant.save()
  await provider.backchannelResult(request, grant)
  res.writeHead(204).end()
}

const handle = provider.callback()

function issuerListener(req, res) {
  const { pathname } = new URL(req.url, urls.op)
  let route
  if (req.method === 'GET' && pathname.startsWith('/interaction/')) {
    route = interaction
  } else if (req.method === 'POST' && pathname === '/harness/ciba-approve') {
    route = approveBackchannel
  } else {
    handle(req, res)
    return
  }
  route(req, res).catch((err) => {
    console.error(`${route.name}:`, err)
    if (!res.headersSent) {
      res.writeHead(500)
    }
    res.end()
  })
}

const tls = {
  cert: readFileSync(join(certs, 'server.crt')),
  key: readFileSync(join(certs, 'server.key')),
}

createServer(tls, issuerListener).listen(ports.op, '127.0.0.1', () => {
  console.log(`oidc-provider: issuer ${urls.op}`)
})
// The mTLS listener requires a client certificate and trusts exactly
// the run's two self-signed client certificates (their own anchors).
// The provider itself still decides what each one may do:
// self_signed_tls_client_auth and certificate binding compare
// thumbprints, not chains.
const clientCertificates = ['client-mtls', 'client-ciba'].map((name) => readFileSync(join(certs, `${name}.crt`)))
createServer({ ...tls, requestCert: true, ca: clientCertificates }, handle).listen(ports.opMTLS, '127.0.0.1', () => {
  console.log(`oidc-provider: mTLS endpoint aliases at ${urls.opMTLS}`)
})
