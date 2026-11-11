// Ports, addresses and URLs shared by setup.mjs, harness.mjs and the
// runner script (which exports the same INTEROP_* variables it reads
// here).
function port(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10)
  if (!Number.isInteger(value) || value <= 0 || value > 65535) {
    throw new Error(`${name} must be a TCP port, got ${process.env[name]}`)
  }
  return value
}

export const ports = {
  keycloak: port('INTEROP_KC_PORT', 29543),
  driver: port('INTEROP_DRIVER_PORT', 29546),
  harness: port('INTEROP_HARNESS_PORT', 29547),
}

// The address the driver's notification endpoint and the harness
// listen on: one the Keycloak container reaches as
// host.docker.internal (the runner works it out).
export const hostAddr = process.env.INTEROP_HOST_ADDR ?? '127.0.0.1'

export const REALM = 'interop'

export const urls = {
  keycloak: `https://localhost:${ports.keycloak}`,
  issuer: `https://localhost:${ports.keycloak}/realms/${REALM}`,
  driver: `https://localhost:${ports.driver}`,
  // The same listeners as Keycloak, inside its container, reaches them.
  driverFromKeycloak: `https://host.docker.internal:${ports.driver}`,
  harnessFromKeycloak: `http://host.docker.internal:${ports.harness}`,
  harness: `http://${hostAddr}:${ports.harness}`,
}

// The one end user. Keycloak resolves CIBA's login_hint as a username.
export const USERNAME = 'interop-user'
export const ACCOUNTS_SCOPE = 'accounts'
