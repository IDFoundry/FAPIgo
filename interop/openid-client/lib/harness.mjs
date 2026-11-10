// Shared plumbing for the legs: the run's client registry and keys,
// TLS-aware fetch functions for openid-client's customFetch, and the
// two interactions a real user would perform (the consent form and a
// CIBA approval), driven over HTTP the same way the OIDF suite's
// browser and automated approval drive them.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { webcrypto } from 'node:crypto'
import * as client from 'openid-client'
import { Agent, fetch as undiciFetch } from 'undici'

import { urls } from './env.mjs'

export function loadRun(workDir) {
  const certs = join(workDir, 'certs')
  const read = (name) => readFileSync(join(certs, name))
  const registry = JSON.parse(readFileSync(join(workDir, 'clients.json'), 'utf8'))
  const ca = read('ca.crt')
  return {
    registry,
    ca,
    serverCert: read('server.crt'),
    serverKey: read('server.key'),
    // Trusts only this run's test CA; presents no client certificate.
    fetch: tlsFetch({ ca }),
    // Trusts the test CA and presents a client certificate whenever a
    // listener asks for one (only the -mtls listener does).
    mtlsFetch: (name) => tlsFetch({ ca, cert: read(`${name}.crt`), key: read(`${name}.key`) }),
  }
}

function tlsFetch(connect) {
  const dispatcher = new Agent({ connect })
  return (url, options) => undiciFetch(url, { ...options, dispatcher })
}

export async function signingKey(run, clientId) {
  const jwk = run.registry.clients[clientId].privateJwk
  const key = await webcrypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  return { key, kid: jwk.kid }
}

// discover returns an openid-client Configuration for clientId, every
// request (discovery included) made through fetchFn.
export function discover(issuer, clientId, metadata, auth, fetchFn) {
  return client.discovery(new URL(issuer), clientId, metadata, auth, {
    [client.customFetch]: fetchFn,
  })
}

// approveConsent plays the user at conformance-as's consent page: it
// opens the authorization URL, reads the form conformance-as renders,
// submits it with decision=approve and returns the redirect back to
// the client (the URL openid-client then processes as its callback).
export async function approveConsent(run, issuer, authorizationURL) {
  const page = await run.fetch(authorizationURL.href, { redirect: 'manual' })
  const html = await page.text()
  if (page.status !== 200) {
    throw new Error(`authorization endpoint: HTTP ${page.status}: ${html.slice(0, 300)}`)
  }
  const handle = formValue(html, 'handle')
  const subject = formValue(html, 'subject')
  const form = new URLSearchParams({ handle, subject, decision: 'approve' })
  for (const [, scope] of html.matchAll(/name="scope" value="([^"]*)"/g)) {
    form.append('scope', scope)
  }
  const decision = await run.fetch(`${issuer}/authorize/decision`, {
    method: 'POST',
    body: form,
    redirect: 'manual',
  })
  const location = decision.headers.get('location')
  if (decision.status !== 303 || !location) {
    throw new Error(`consent decision: HTTP ${decision.status}: ${(await decision.text()).slice(0, 300)}`)
  }
  await decision.body?.cancel()
  return new URL(location)
}

function formValue(html, name) {
  const match = html.match(new RegExp(`name="${name}" value="([^"]*)"`))
  if (!match) {
    throw new Error(`consent page has no ${name} field`)
  }
  return match[1]
}

// approveBackchannel plays the user's authentication device for a CIBA
// request: conformance-as's POST /backchannel-approve, the endpoint the
// OIDF suite's automated approval calls.
export async function approveBackchannel(run, issuer, authReqId) {
  const url = new URL(`${issuer}/backchannel-approve`)
  url.searchParams.set('auth_req_id', authReqId)
  url.searchParams.set('action', 'allow')
  const res = await run.fetch(url.href, { method: 'POST' })
  if (res.status !== 200) {
    throw new Error(`backchannel approval: HTTP ${res.status}: ${await res.text()}`)
  }
  await res.body?.cancel()
}

// fetchUserInfoAndResource calls UserInfo and the /accounts resource
// over the mTLS listener with a certificate-bound access token, checking
// UserInfo's sub against the ID token's.
export async function fetchUserInfoAndResource(config, tokens) {
  const sub = tokens.claims().sub
  const userinfo = await client.fetchUserInfo(config, tokens.access_token, sub)
  if (userinfo.sub !== sub) {
    throw new Error(`userinfo sub ${userinfo.sub} != ID token sub ${sub}`)
  }
  const resource = await client.fetchProtectedResource(config, tokens.access_token, new URL(`${urls.asMTLS}/accounts`), 'GET')
  if (resource.status !== 200) {
    throw new Error(`resource call: HTTP ${resource.status}: ${await resource.text()}`)
  }
  await resource.body?.cancel()
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export { urls }
