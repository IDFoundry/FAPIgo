// Ports and URLs shared by setup.mjs, server.mjs and the runner script
// (which exports the same INTEROP_* variables it reads here).
function port(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10)
  if (!Number.isInteger(value) || value <= 0 || value > 65535) {
    throw new Error(`${name} must be a TCP port, got ${process.env[name]}`)
  }
  return value
}

export const ports = {
  op: port('INTEROP_OP_PORT', 29443),
  opMTLS: port('INTEROP_OP_MTLS_PORT', 29444),
  driver: port('INTEROP_DRIVER_PORT', 29446),
}

export const urls = {
  op: `https://localhost:${ports.op}`,
  opMTLS: `https://localhost:${ports.opMTLS}`,
  driver: `https://localhost:${ports.driver}`,
}

// The one end user: the interaction routes sign them in and consent on
// their behalf, and CIBA's login_hint names them.
export const ACCOUNT_ID = 'interop-user'

// The resource indicator (RFC 8707) the client_credentials leg asks
// for, and the scope the provider issues for it.
export const ACCOUNTS_RESOURCE = `${urls.op}/accounts`
export const ACCOUNTS_SCOPE = 'accounts'
