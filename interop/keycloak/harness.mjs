// The CIBA authentication device for the Keycloak interop run, over
// plain HTTP on the address the runner gives (INTEROP_HOST_ADDR):
//
//   node harness.mjs
//
// Keycloak hands each CIBA request to an "authentication channel": with
// its HTTP channel provider, it POSTs the request to POST /channel here
// with a bearer token naming that request. The driver then approves it
// through POST /approve (form parameter auth_req_id), in place of the
// user's device, and the harness completes it through Keycloak's
// channel callback endpoint with that bearer token.
//
// Keycloak doesn't pass the auth_req_id to the channel, and the driver
// runs one leg at a time, so /approve completes the oldest request still
// waiting. A test fixture: nothing here authenticates anyone.
import { createServer } from 'node:http'

import { hostAddr, ports, urls, USERNAME } from './lib/env.mjs'

const callback = `${urls.issuer}/protocol/openid-connect/ext/ciba/auth/callback`
const pending = []
const maxBody = 64 * 1024

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = ''
    req.setEncoding('utf8')
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > maxBody) {
        reject(new Error('request body too large'))
        req.destroy()
      }
    })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

function reply(res, status, text = '') {
  res.writeHead(status, { 'content-type': 'text/plain' })
  res.end(text)
}

async function channel(req, res) {
  const auth = req.headers.authorization ?? ''
  if (!auth.startsWith('Bearer ')) {
    return reply(res, 401, 'missing bearer token')
  }
  const request = JSON.parse(await readBody(req))
  if (request.login_hint !== USERNAME) {
    return reply(res, 400, `unknown login_hint ${request.login_hint}`)
  }
  pending.push(auth.slice('Bearer '.length))
  console.log(`harness: authentication request for ${request.login_hint} (binding_message ${request.binding_message})`)
  return reply(res, 201)
}

async function approve(req, res) {
  const authReqID = new URLSearchParams(await readBody(req)).get('auth_req_id')
  const channelToken = pending.shift()
  if (!authReqID || !channelToken) {
    return reply(res, 400, 'no authentication request is waiting')
  }
  const result = await fetch(callback, {
    method: 'POST',
    headers: { authorization: `Bearer ${channelToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ status: 'SUCCEED' }),
  })
  if (!result.ok) {
    return reply(res, 502, `callback returned ${result.status}: ${await result.text()}`)
  }
  console.log('harness: approved the waiting request')
  return reply(res, 204)
}

const routes = { '/channel': channel, '/approve': approve }

createServer((req, res) => {
  const route = req.method === 'POST' ? routes[new URL(req.url, 'http://harness').pathname] : undefined
  if (!route) {
    return reply(res, 404)
  }
  route(req, res).catch((err) => reply(res, 500, String(err)))
}).listen(ports.harness, hostAddr, () => {
  console.log(`harness: listening on ${hostAddr}:${ports.harness}`)
})
