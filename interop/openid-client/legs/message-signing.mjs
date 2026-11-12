// Leg 3: FAPI 2.0 Message Signing — a signed request object (JAR,
// RFC 9101) pushed via PAR, and a JARM response (response_mode=jwt)
// that openid-client verifies, with private_key_jwt and DPoP-bound
// tokens, against the message-signing instance. This client signs
// with PS256 throughout (client assertion, request object and DPoP
// proofs), the other legs with ES256.
import assert from 'node:assert/strict'
import * as client from 'openid-client'

import { approveConsent, discover, signingKey, urls } from '../lib/harness.mjs'

const CLIENT_ID = 'fapigo-ms-pkjwt-dpop'

export default async function messageSigning(run) {
  const key = await signingKey(run, CLIENT_ID)
  const config = await discover(urls.asMessageSigning, CLIENT_ID, undefined, client.PrivateKeyJwt(key), run.fetch)
  client.useJwtResponseMode(config)
  const DPoP = client.getDPoPHandle(config, await client.randomDPoPKeyPair('PS256'))

  const codeVerifier = client.randomPKCECodeVerifier()
  const state = client.randomState()
  const nonce = client.randomNonce()
  // openid-client's documented JAR + PAR composition: sign the request
  // object, then push the resulting parameters.
  const signed = await client.buildAuthorizationUrlWithJAR(config, {
    redirect_uri: run.registry.redirectURI,
    scope: 'openid offline_access accounts',
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  }, key)
  assert.ok(signed.searchParams.get('request'), 'openid-client signed a request object')
  const authorizationURL = await client.buildAuthorizationUrlWithPAR(config, signed.searchParams, { DPoP })

  const callback = await approveConsent(run, urls.asMessageSigning, authorizationURL)
  assert.ok(callback.searchParams.get('response'), 'authorization response is a JARM JWT')
  assert.equal(callback.searchParams.get('code'), null, 'no bare code next to the JARM response')

  const tokens = await client.authorizationCodeGrant(config, callback, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
    idTokenExpected: true,
  }, undefined, { DPoP })
  assert.equal(tokens.token_type.toLowerCase(), 'dpop')
  const sub = tokens.claims().sub

  const userinfo = await client.fetchUserInfo(config, tokens.access_token, sub, { DPoP })
  assert.equal(userinfo.sub, sub)

  const resource = await client.fetchProtectedResource(config, tokens.access_token, new URL(`${urls.asMessageSigning}/accounts`), 'GET', undefined, undefined, { DPoP })
  assert.equal(resource.status, 200)
  await resource.body?.cancel()
}
