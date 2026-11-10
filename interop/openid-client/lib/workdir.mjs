// The work directory setup.mjs writes into and run.mjs reads from: the
// runner's mktemp -d directory, passed as the first argument. Anything
// that doesn't resolve to a directory inside the system temporary
// directory is refused, so a mistyped argument can't make either script
// read or write elsewhere.
import { realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve, sep } from 'node:path'

export function workDirFromArgs(usage) {
  const arg = process.argv[2]
  if (!arg) {
    throw new Error(`usage: ${usage}`)
  }
  const root = realpathSync(tmpdir())
  const dir = realpathSync(resolve(arg))
  if (!dir.startsWith(root + sep)) {
    throw new Error(`work directory ${dir} is not inside ${root}`)
  }
  return dir
}
