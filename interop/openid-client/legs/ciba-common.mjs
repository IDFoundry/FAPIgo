// Shared by the CIBA legs. FAPI-CIBA sender-constrains tokens with mTLS
// (the OIDF FAPI-CIBA plan has no DPoP variant), so these clients
// authenticate with private_key_jwt but call the mtls_endpoint_aliases
// with a client certificate.
import * as client from 'openid-client'

import { discover, signingKey, urls } from '../lib/harness.mjs'
import { SUBJECT } from '../lib/env.mjs'

export async function cibaClient(run, clientId) {
  const key = await signingKey(run, clientId)
  const config = await discover(urls.as, clientId, { use_mtls_endpoint_aliases: true }, client.PrivateKeyJwt(key), run.mtlsFetch('client-ciba'))
  return { config, key }
}

// signedAuthenticationRequest builds the signed authentication request
// FAPI-CIBA requires (CIBA Core §7.1.1). openid-client has no
// CIBA-specific signer, so this uses its JAR signer
// (buildAuthorizationUrlWithJAR), which produces exactly the claims
// §7.1.1 requires — iss, aud (the issuer), exp, iat, nbf and jti —
// around the CIBA parameters; it also adds client_id and
// response_type=code, which a CIBA server ignores.
export async function signedAuthenticationRequest(config, key, extra = {}) {
  const signed = await client.buildAuthorizationUrlWithJAR(config, {
    scope: 'openid offline_access accounts',
    login_hint: SUBJECT,
    binding_message: 'interop test',
    ...extra,
  }, key)
  return signed.searchParams.get('request')
}
