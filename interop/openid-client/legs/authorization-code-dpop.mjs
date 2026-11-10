// Leg 1: authorization code + PAR + PKCE (S256) + private_key_jwt +
// DPoP-bound tokens, against the FAPI 2.0 Security Profile instance.
// openid-client validates the ID token and answers every
// use_dpop_nonce challenge (PAR, token, UserInfo, resource) itself.
import assert from 'node:assert/strict'
import * as client from 'openid-client'

import { approveConsent, discover, signingKey, urls } from '../lib/harness.mjs'

const CLIENT_ID = 'fapigo-sp-pkjwt-dpop'

export default async function authorizationCodeDPoP(run) {
  const config = await discover(urls.as, CLIENT_ID, undefined, client.PrivateKeyJwt(await signingKey(run, CLIENT_ID)), run.fetch)
  const DPoP = client.getDPoPHandle(config, await client.randomDPoPKeyPair('ES256'))

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
  }, { DPoP })
  assert.ok(authorizationURL.searchParams.get('request_uri'), 'PAR returned a request_uri')

  const callback = await approveConsent(run, urls.as, authorizationURL)
  const tokens = await client.authorizationCodeGrant(config, callback, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
    idTokenExpected: true,
  }, undefined, { DPoP })
  assert.equal(tokens.token_type.toLowerCase(), 'dpop', 'access token is DPoP-bound')
  const sub = tokens.claims().sub
  assert.ok(sub, 'ID token has a sub')
  assert.ok(tokens.refresh_token, 'offline_access granted a refresh token')

  const userinfo = await client.fetchUserInfo(config, tokens.access_token, sub, { DPoP })
  assert.equal(userinfo.sub, sub)

  const accountsURL = new URL(`${urls.as}/accounts`)
  const resource = await client.fetchProtectedResource(config, tokens.access_token, accountsURL, 'GET', undefined, undefined, { DPoP })
  assert.equal(resource.status, 200, 'resource call with the DPoP-bound token')
  await resource.body?.cancel()

  const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token, undefined, { DPoP })
  assert.equal(refreshed.token_type.toLowerCase(), 'dpop', 'refreshed access token is DPoP-bound')
  const again = await client.fetchProtectedResource(config, refreshed.access_token, accountsURL, 'GET', undefined, undefined, { DPoP })
  assert.equal(again.status, 200, 'resource call with the refreshed token')
  await again.body?.cancel()
}
