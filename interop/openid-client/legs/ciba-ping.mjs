// Leg 6: CIBA ping mode. The harness serves the client notification
// endpoint over HTTPS (a certificate from this run's test CA), checks
// the ping's bearer token and auth_req_id (CIBA Core §10.2), then has
// openid-client redeem the auth_req_id.
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:https'
import * as client from 'openid-client'

import { approveBackchannel, fetchUserInfoAndResource, urls } from '../lib/harness.mjs'
import { ports } from '../lib/env.mjs'
import { cibaClient, signedAuthenticationRequest } from './ciba-common.mjs'

const CLIENT_ID = 'fapigo-ciba-ping-pkjwt'
const NOTIFICATION_TIMEOUT_MS = 30_000

function notificationEndpoint(run) {
  let deliver
  const received = new Promise((resolve) => { deliver = resolve })
  const server = createServer({ cert: run.serverCert, key: run.serverKey }, (req, res) => {
    if (req.method !== 'POST' || req.url !== '/ciba-notify') {
      res.writeHead(404).end()
      return
    }
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      res.writeHead(204).end()
      deliver({
        authorization: req.headers.authorization,
        contentType: req.headers['content-type'],
        body: Buffer.concat(chunks).toString('utf8'),
      })
    })
  })
  return { server, received }
}

export default async function cibaPing(run) {
  const { server, received } = notificationEndpoint(run)
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(ports.harness, '127.0.0.1', resolve)
  })
  try {
    const { config, key } = await cibaClient(run, CLIENT_ID)
    const notificationToken = randomBytes(32).toString('base64url')
    const request = await signedAuthenticationRequest(config, key, { client_notification_token: notificationToken })
    const authReq = await client.initiateBackchannelAuthentication(config, { request })
    assert.ok(authReq.auth_req_id)

    await approveBackchannel(run, urls.as, authReq.auth_req_id)
    let timer
    const ping = await Promise.race([
      received,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('no ping notification received')), NOTIFICATION_TIMEOUT_MS)
      }),
    ]).finally(() => clearTimeout(timer))
    assert.equal(ping.authorization, `Bearer ${notificationToken}`, 'ping carries the client_notification_token')
    assert.match(ping.contentType ?? '', /^application\/json/)
    assert.deepEqual(JSON.parse(ping.body), { auth_req_id: authReq.auth_req_id })

    const tokens = await client.pollBackchannelAuthenticationGrant(config, authReq)
    assert.equal(tokens.token_type.toLowerCase(), 'bearer')
    await fetchUserInfoAndResource(config, tokens)
  } finally {
    server.closeAllConnections()
    await new Promise((resolve) => server.close(resolve))
  }
}
