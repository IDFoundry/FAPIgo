// Ports and URLs shared by setup.mjs, run.mjs and the runner script
// (which exports the same INTEROP_* variables it reads here).
function port(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10)
  if (!Number.isInteger(value) || value <= 0 || value > 65535) {
    throw new Error(`${name} must be a TCP port, got ${process.env[name]}`)
  }
  return value
}

export const ports = {
  as: port('INTEROP_AS_PORT', 28443),
  asMTLS: port('INTEROP_AS_MTLS_PORT', 28444),
  asMessageSigning: port('INTEROP_AS_MS_PORT', 28445),
  harness: port('INTEROP_HARNESS_PORT', 28446),
}

export const urls = {
  as: `https://localhost:${ports.as}`,
  asMTLS: `https://localhost:${ports.asMTLS}`,
  asMessageSigning: `https://localhost:${ports.asMessageSigning}`,
  harness: `https://localhost:${ports.harness}`,
}

// The subject conformance-as authenticates every consent and CIBA
// approval as (its default_subject).
export const SUBJECT = 'interop-user'
