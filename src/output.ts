// Report output safety. Reports are the only user-requested writes; they must
// never clobber the audited artifact, anything inside it, or each other.
//
// macOS volumes are case-insensitive by default, so every comparison uses the
// on-disk spelling (realpath.native) AND is case/NFC-folded: "myapp.app/contents"
// and "MyApp.app/Contents" are the same directory. Folding can only over-refuse
// on a case-sensitive volume, never under-refuse.

import { closeSync, constants, existsSync, fstatSync, ftruncateSync, lstatSync, openSync, realpathSync, statSync, writeSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";

export interface OutputTarget {
  flag: string;
  path: string;
}

function realOrSelf(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    return resolve(p);
  }
}

/** Fully resolved destination (parent realpath + final component; final symlinks are followed). */
function resolveDestination(p: string): string {
  const abs = resolve(p);
  try {
    if (lstatSync(abs).isSymbolicLink()) return realpathSync.native(abs);
  } catch {
    // does not exist yet
  }
  return join(realOrSelf(dirname(abs)), basename(abs));
}

function fold(p: string): string {
  return p.normalize("NFC").toLowerCase();
}

function insideOrEqual(dest: string, root: string): boolean {
  const d = fold(dest);
  const r = fold(root);
  return d === r || d.startsWith(r.endsWith(sep) ? r : r + sep);
}

/**
 * Returns an error message when a destination is unsafe, else undefined.
 * Unsafe: equals/inside the input artifact or its .app bundle (case-folded),
 * same inode as the artifact, a hard-linked existing file (nlink > 1, which
 * may be a file inside the bundle), an existing file without `force`, a
 * non-regular existing destination, or a duplicate of another output.
 */
export function validateOutputs(input: string, outputs: OutputTarget[], force = false): string | undefined {
  const artifact = realOrSelf(input);
  let artifactStat;
  try {
    artifactStat = statSync(artifact);
  } catch {
    artifactStat = undefined;
  }
  const seen = new Map<string, string>();
  for (const o of outputs) {
    const dest = resolveDestination(o.path);
    if (insideOrEqual(dest, artifact)) {
      return `${o.flag} ${o.path} would overwrite or write inside the audited artifact`;
    }
    // Also guard the app bundle that a Contents/ or executable input belongs to.
    const appMatch = /^(.*?\.app)(\/|$)/i.exec(artifact);
    if (appMatch !== null && insideOrEqual(dest, appMatch[1] as string)) {
      return `${o.flag} ${o.path} is inside the audited .app bundle`;
    }
    if (existsSync(dest)) {
      const st = statSync(dest);
      if (artifactStat !== undefined && st.ino === artifactStat.ino && st.dev === artifactStat.dev) {
        return `${o.flag} ${o.path} is the same file as the audited artifact`;
      }
      // Non-regular destinations (directories etc.) are left to fail at write time (exit 5, report still printed).
      if (st.isFile() && st.nlink > 1) {
        return `${o.flag} ${o.path} is a hard-linked file (${st.nlink} links); it could be a file inside the audited artifact, so it is never overwritten`;
      }
      if (st.isFile() && !force) return `${o.flag} ${o.path} already exists (pass --force to overwrite it)`;
    }
    const key = fold(dest);
    const prior = seen.get(key);
    if (prior !== undefined) return `${o.flag} and ${prior} point at the same file`;
    seen.set(key, o.flag);
  }
  return undefined;
}

/**
 * Create the report with O_EXCL|O_NOFOLLOW (never replace, never follow a
 * final symlink). With `force`, an existing regular single-link file is
 * truncated through an O_NOFOLLOW descriptor after fstat re-verifies it.
 */
export function writeReport(path: string, content: string, force = false): void {
  const dest = resolveDestination(path);
  const base = constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW;
  const fd = openSync(dest, force ? base : base | constants.O_EXCL, 0o644);
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink > 1) throw new Error("destination is not a single-link regular file");
    ftruncateSync(fd, 0);
    const buf = Buffer.from(content);
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
  } finally {
    closeSync(fd);
  }
}
