// Leg 2: authorization code + PAR + PKCE with self_signed_tls_client_auth
// and certificate-bound tokens (RFC 8705), every client-authenticated
// and protected call going to the mtls_endpoint_aliases.
import assert from 'node:assert/strict'
import * as client from 'openid-client'

import { approveConsent, discover, urls } from '../lib/harness.mjs'

const CLIENT_ID = 'fapigo-sp-mtls-mtls'

export default async function authorizationCodeMTLS(run) {
  const fetchWithCert = run.mtlsFetch('client-mtls')
  const config = await discover(urls.as, CLIENT_ID, { use_mtls_endpoint_aliases: true }, client.TlsClientAuth(), fetchWithCert)
  const md = config.serverMetadata()
  assert.equal(md.tls_client_certificate_bound_access_tokens, true, 'server advertises certificate-bound tokens')
  assert.ok(md.mtls_endpoint_aliases?.token_endpoint, 'server advertises mtls_endpoint_aliases')

  const codeVerifier = client.randomPKCECodeVerifier()
  const state = client.randomState()
  const nonce = client.randomNonce()
  const authorizationURL = await client.buildAuthorizationUrlWithPAR(config, {
    redirect_uri: run.registry.redirectURI,
    scope: 'openid offline_access accounts',
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  })

  const callback = await approveConsent(run, urls.as, authorizationURL)
  const tokens = await client.authorizationCodeGrant(config, callback, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
    idTokenExpected: true,
  })
  assert.equal(tokens.token_type.toLowerCase(), 'bearer')
  const sub = tokens.claims().sub

  // fetchUserInfo follows mtls_endpoint_aliases.userinfo_endpoint.
  const userinfo = await client.fetchUserInfo(config, tokens.access_token, sub)
  assert.equal(userinfo.sub, sub)

  const resource = await client.fetchProtectedResource(config, tokens.access_token, new URL(`${urls.asMTLS}/accounts`), 'GET')
  assert.equal(resource.status, 200, 'resource call over mTLS with the certificate-bound token')
  await resource.body?.cancel()

  const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token)
  assert.ok(refreshed.access_token, 'refresh over the mTLS token endpoint alias')
}
