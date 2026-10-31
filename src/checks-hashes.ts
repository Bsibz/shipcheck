// Hashes: SHA-256 of the artifacts people actually verify by hand.
// Default: main executable + framework binaries + helper executables.
// --hashes all adds asar files and native modules (big).

import type { AuditContext } from "./checkscommon.js";
import { GROUP, info, pass, warn } from "./checkscommon.js";
import { sha256File } from "./hashes.js";

const H = GROUP.hashes;

export async function runHashChecks(ctx: AuditContext): Promise<void> {
  const app = ctx.app;
  if (app === undefined || ctx.opts.hashes === "none") return;

  const targets: Array<{ abs: string; rel: string }> = [];
  if (app.execPath !== undefined) targets.push({ abs: app.execPath, rel: relOf(app, app.execPath) });
  for (const f of app.frameworkBinaries) {
    targets.push({ abs: f, rel: relOf(app, f) });
  }
  if (ctx.opts.hashes === "all") {
    for (const a of app.asarPaths) targets.push({ abs: a, rel: relOf(app, a) });
    for (const m of app.nativeModules) targets.push({ abs: m.abs, rel: m.rel });
  }

  const MAX_HASHED = 24;
  const results: string[] = [];
  const failed: string[] = [];
  const toHash = targets.slice(0, MAX_HASHED);
  const notAttempted = targets.length - toHash.length;
  for (const t of toHash) {
    try {
      const hash = await sha256File(t.abs);
      if (hash === undefined) failed.push(t.rel);
      else results.push(`${hash}  ${t.rel}`);
    } catch {
      failed.push(t.rel);
    }
  }

  if (results.length === 0) {
    ctx.collector.add(warn("hashes.executables", H, "Key executables could not be hashed.", failed.slice(0, 8)));
    return;
  }
  const complete = failed.length === 0 && notAttempted === 0;
  const gaps: string[] = [];
  if (notAttempted > 0) gaps.push(`${notAttempted} more not hashed (cap ${MAX_HASHED}; hashes cover the first ${MAX_HASHED} of ${targets.length})`);
  if (failed.length > 0) gaps.push(`${failed.length} failed to hash`);
  const evidence = [...results, ...failed.slice(0, 8).map((rel) => `(hash failed)  ${rel}`)];
  if (notAttempted > 0) evidence.push(`(not hashed: ${notAttempted} of ${targets.length} targets beyond the cap)`);
  ctx.collector.add({
    id: "hashes.executables",
    group: H,
    // A partial inventory is not a pass: say exactly what is and is not covered.
    status: complete ? "pass" : failed.length > 0 ? "warn" : "info",
    detail: complete
      ? `SHA-256 recorded for ${results.length} of ${targets.length} artifact(s).`
      : `SHA-256 recorded for ${results.length} of ${targets.length} artifact(s); ${gaps.join("; ")}.`,
    evidence,
  });
  void info;
}

function relOf(app: { bundlePath: string }, abs: string): string {
  return abs.startsWith(app.bundlePath) ? abs.slice(app.bundlePath.length + 1) : abs;
}
