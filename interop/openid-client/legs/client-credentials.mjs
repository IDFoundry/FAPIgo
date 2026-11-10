// Leg 4: client_credentials (RFC 6749 §4.4) with private_key_jwt and a
// DPoP-bound access token, then a resource call with it.
import assert from 'node:assert/strict'
import * as client from 'openid-client'

import { discover, signingKey, urls } from '../lib/harness.mjs'

const CLIENT_ID = 'fapigo-sp-cc-pkjwt-dpop'

export default async function clientCredentials(run) {
  const config = await discover(urls.as, CLIENT_ID, undefined, client.PrivateKeyJwt(await signingKey(run, CLIENT_ID)), run.fetch)
  const DPoP = client.getDPoPHandle(config, await client.randomDPoPKeyPair('ES256'))

  const tokens = await client.clientCredentialsGrant(config, { scope: 'accounts' }, { DPoP })
  assert.equal(tokens.token_type.toLowerCase(), 'dpop')
  assert.equal(tokens.refresh_token, undefined, 'no refresh token for client_credentials')

  const resource = await client.fetchProtectedResource(config, tokens.access_token, new URL(`${urls.as}/accounts`), 'GET', undefined, undefined, { DPoP })
  assert.equal(resource.status, 200)
  await resource.body?.cancel()
}
