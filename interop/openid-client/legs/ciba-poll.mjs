// Leg 5: CIBA poll mode. openid-client starts polling (meeting
// authorization_pending at least once), the user approves on their
// device (conformance-as's /backchannel-approve), and the poll then
// redeems the auth_req_id for certificate-bound tokens.
import assert from 'node:assert/strict'
import * as client from 'openid-client'

import { approveBackchannel, fetchUserInfoAndResource, sleep, urls } from '../lib/harness.mjs'
import { cibaClient, signedAuthenticationRequest } from './ciba-common.mjs'

const CLIENT_ID = 'fapigo-ciba-poll-pkjwt'

export default async function cibaPoll(run) {
  const { config, key } = await cibaClient(run, CLIENT_ID)
  const request = await signedAuthenticationRequest(config, key)
  const authReq = await client.initiateBackchannelAuthentication(config, { request })
  assert.ok(authReq.auth_req_id)
  assert.ok(authReq.interval, 'poll mode returns an interval')

  const polling = client.pollBackchannelAuthenticationGrant(config, authReq)
  // Approve only after the first poll has come back pending.
  await sleep((authReq.interval + 1) * 1000)
  await approveBackchannel(run, urls.as, authReq.auth_req_id)
  const tokens = await polling

  assert.equal(tokens.token_type.toLowerCase(), 'bearer')
  assert.ok(tokens.refresh_token, 'offline_access granted a refresh token')
  await fetchUserInfoAndResource(config, tokens)
}
