// Path/hygiene scan: leftover local build paths where safely detectable.
//
// Surfaces (read-only):
//   1. Info.plist string values — parsed plist, so no encoding tricks.
//   2. asar header JSON — file index sometimes keeps absolute build paths.
//   3. main executable + helper executables (+ all framework binaries with
//      --paths-scan all) — byte scan for /Users/…, /home/…, /tmp/…, etc.
//
// Findings are worded to allow false positives (docs, comments can match) —
// the evidence is the count and samples, and a real fix depends on who owns
// the string.

import type { AuditContext } from "./checkscommon.js";
import { GROUP, pass, unknown, warn } from "./checkscommon.js";
import { scanBinaryForBuildPaths, scanPlistStrings } from "./pathscan.js";
import { scanHeaderForBuildPaths } from "./asar.js";

const P = GROUP.paths;

export function runPathScanChecks(ctx: AuditContext): void {
  const app = ctx.app;
  if (app === undefined) return;

  // 1. Info.plist
  const dict = app.infoPlist.dict;
  if (dict !== undefined) {
    const scan = scanPlistStrings(dict, "Info.plist");
    if (scan.hits.length > 0) {
      ctx.collector.add(
        warn(
          "paths.info-plist",
          P,
          `Info.plist carries ${scan.hits.length} generator-host absolute path(s) — usually leaked build-machine details.`,
          scan.hits.slice(0, 5),
          "Check packaging config for hardcoded build paths.",
        ),
      );
    } else {
      ctx.collector.add(pass("paths.info-plist", P, "Info.plist is free of generator-host paths."));
    }
  }

  // 2. asar headers
  for (const asar of app.asarPaths) {
    const hits = scanHeaderForBuildPaths(asar);
    if (hits.length === 0) continue;
    ctx.collector.add(
      warn(
        "paths.asar-header",
        P,
        `asar header (file index) of ${relOf(app, asar)} contains ${hits.length} build-host path sample(s).`,
        hits.slice(0, 4),
        "Builders sometimes persist absolute paths into the index; strip them in the packaging step.",
      ),
    );
  }

  // 3. binaries
  const surfaces: string[] = [app.execPath ?? ""];
  if (ctx.opts.pathsScan === "all") {
    for (const f of app.frameworkBinaries) surfaces.push(f);
  }
  const findings: string[] = [];
  let scannedCompletely = 0;
  const incomplete: string[] = [];
  for (const s of surfaces) {
    if (s === undefined || s === "") continue;
    const scan = scanBinaryForBuildPaths(s, 6);
    if (scan.complete === false) incomplete.push(relOf(app, s));
    else scannedCompletely += 1;
    if (scan.hits.length > 0) {
      findings.push(`${relOf(app, s)}: ${scan.hits.length} sample(s)`);
    }
  }
  if (findings.length > 0) {
    ctx.collector.add(
      warn(
        "paths.executables",
        P,
        "Mach-O binaries contain build-host path text — common in dev builds, worth stripping for a clean release.",
        [...findings.slice(0, 4)],
        "Usually harmless strings; check for anything that would break on a user machine (e.g. toolchain paths).",
      ),
    );
  } else if (scannedCompletely === 0 || incomplete.length > 0) {
    ctx.collector.add(
      unknown(
        "paths.executables",
        P,
        scannedCompletely === 0
          ? "No Mach-O binary could be scanned for build-host paths (missing, refused or unreadable); not a clean result."
          : `No build-host path text found in ${scannedCompletely} fully scanned binary(ies), but ${incomplete.length} could not be fully scanned.`,
        incomplete.slice(0, 4),
      ),
    );
  } else {
    ctx.collector.add(pass("paths.executables", P, `No build-host path text found in ${scannedCompletely} scanned Mach-O binary(ies).`));
  }
}

function relOf(app: { bundlePath: string }, abs: string): string {
  return abs.startsWith(app.bundlePath) ? abs.slice(app.bundlePath.length + 1) : abs;
}
