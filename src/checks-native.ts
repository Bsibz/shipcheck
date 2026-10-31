// Native code load-target checks.
//
// Candidate main/helper executables, frameworks, native extensions and files
// with execute bits are read with `otool -arch all -l` (600-image cap).
// A partial model compares each slice's load paths with confined regular files.
//
// Failure classes this targets (seen in real Electron releases):
//   - a dependency that names the build host (/Users/dev, /opt/homebrew, …):
//     works on the build machine only;
//   - @loader_path / @executable_path dependencies whose file is not there;
//   - @rpath dependencies that resolve through none of the image's or the
//     executable's LC_RPATH entries — even when a same-named file sits
//     somewhere else in the bundle, the modeled paths do not reach it;
//   - a deployment target above LSMinimumSystemVersion, or code built for
//     another Apple platform.
//
// All of this is static. Dynamic dlopen paths, DYLD_* variables, Electron ABI
// compatibility and hardware behaviour need a runtime test.

import { lstatSync, statSync } from "node:fs";
import { basename, dirname } from "node:path";
import type { AuditContext } from "./checkscommon.js";
import { GROUP, run, unknown, warn } from "./checkscommon.js";
import { containedRealPath, type AppStructure } from "./bundle.js";
import { getString } from "./plist.js";
import {
  compareVersions,
  isMacLoadablePlatform,
  isMachOFile,
  parseLoadCommands,
  platformName,
  resolveDependency,
  type DepCommand,
  type ExecutableContext,
  type MachoSlice,
} from "./macho.js";

const N = GROUP.native;

/** Upper bound on otool invocations per run (each is a process spawn). */
export const MAX_MACHO_ANALYZED = 600;

export type MachoRole = "main" | "helper-executable" | "framework" | "node" | "dylib" | "other";

export interface MachoTarget {
  abs: string;
  rel: string;
  role: MachoRole;
}

export interface MachoInventory {
  targets: MachoTarget[];
  /** Candidates beyond MAX_MACHO_ANALYZED that were not analyzed. */
  notAnalyzed: number;
  /** .node/.dylib files whose bytes are not Mach-O (foreign-platform prebuilds, broken files). */
  nonMachoNative: number;
}

function relOf(app: { bundlePath: string }, abs: string): string {
  return abs.startsWith(app.bundlePath + "/") ? abs.slice(app.bundlePath.length + 1) : abs;
}

export function collectMachoTargets(app: AppStructure): MachoInventory {
  const seen = new Set<string>();
  const found: MachoTarget[] = [];
  let nonMachoNative = 0;
  const add = (abs: string, role: MachoRole): void => {
    if (seen.has(abs)) return;
    seen.add(abs);
    found.push({ abs, rel: relOf(app, abs), role });
  };

  const isRegular = (p: string): boolean => {
    try {
      return lstatSync(p).isFile();
    } catch {
      return false;
    }
  };

  if (app.execPath !== undefined && isRegular(app.execPath) && isMachOFile(app.execPath)) add(app.execPath, "main");

  const exeCandidates: string[] = [];
  const otherCandidates: string[] = [];
  for (const e of app.walk.entries) {
    if (e.kind !== "file") continue;
    const name = basename(e.abs);
    if (name.endsWith(".node") || name.endsWith(".dylib")) continue; // handled via nativeModules
    const inMacOS = e.rel.includes("Contents/MacOS/");
    const execBit = ((e.mode ?? 0) & 0o111) !== 0;
    const ext = name.endsWith(".so") || name.endsWith(".bundle");
    if (inMacOS) exeCandidates.push(e.abs);
    else if (execBit || ext) otherCandidates.push(e.abs);
  }
  for (const abs of exeCandidates) if (isMachOFile(abs)) add(abs, "helper-executable");
  for (const abs of app.frameworkBinaries) if (isRegular(abs) && isMachOFile(abs)) add(abs, "framework");
  for (const m of app.nativeModules) {
    if (isMachOFile(m.abs)) add(m.abs, m.kind);
    else nonMachoNative += 1;
  }
  for (const abs of otherCandidates) if (isMachOFile(abs)) add(abs, "other");

  const notAnalyzed = Math.max(0, found.length - MAX_MACHO_ANALYZED);
  return { targets: found.slice(0, MAX_MACHO_ANALYZED), notAnalyzed, nonMachoNative };
}

interface Analyzed {
  target: MachoTarget;
  slices: MachoSlice[];
}

interface Problem {
  rel: string;
  archs: Set<string>;
  target: string;
  cmd: DepCommand;
  elsewhere?: string;
}

function noteProblem(map: Map<string, Problem>, rel: string, arch: string, target: string, cmd: DepCommand, elsewhere?: string): void {
  const key = `${rel}\0${target}\0${cmd}`;
  const hit = map.get(key);
  if (hit !== undefined) {
    if (arch !== "") hit.archs.add(arch);
    return;
  }
  map.set(key, { rel, archs: new Set(arch === "" ? [] : [arch]), target, cmd, elsewhere });
}

function formatProblem(p: Problem): string {
  const archs = p.archs.size > 0 ? ` [${[...p.archs].join(",")}]` : "";
  const weak = p.cmd === "LC_LOAD_WEAK_DYLIB" ? " (weak)" : p.cmd === "LC_LAZY_LOAD_DYLIB" ? " (lazy)" : "";
  const where = p.elsewhere !== undefined ? ` — a file with this name exists at ${p.elsewhere}` : "";
  return `${p.rel}${archs} → ${p.target}${weak}${where}`;
}

const isOptional = (cmd: DepCommand): boolean => cmd === "LC_LOAD_WEAK_DYLIB";

export function runNativeChecks(ctx: AuditContext): void {
  const app = ctx.app;
  if (app === undefined) return;

  const inv = collectMachoTargets(app);
  if (inv.targets.length === 0) {
    ctx.collector.add({
      id: "native.inventory",
      group: N,
      status: "info",
      detail:
        inv.nonMachoNative > 0
          ? `No recognized Mach-O images found; ${inv.nonMachoNative} .node/.dylib file(s) may be foreign, malformed or unreadable.`
          : "No Mach-O native payload found in the bundle.",
    });
    if (inv.nonMachoNative > 0 || app.walk.capped) ctx.collector.add(unknown("native.coverage", N, "Native payloads were not fully inspected: unrecognized bytes or a capped bundle inventory. No clean native verdict is claimed."));
    return;
  }

  const analyzed: Analyzed[] = [];
  const unreadable: string[] = [];
  let tooling: string | undefined;
  for (const t of inv.targets) {
    const r = run(ctx, "otool", ["-arch", "all", "-l", t.abs], 1024);
    if (r.status !== "ok") {
      tooling = `otool ${r.status}${r.errorCode !== undefined ? ` (${r.errorCode})` : ""}`;
      unreadable.push(t.rel);
      if (r.status === "missing") {
        unreadable.push(...inv.targets.slice(analyzed.length + unreadable.length).map((target) => target.rel));
        break;
      }
      continue;
    }
    if (r.code !== 0) {
      unreadable.push(t.rel);
      continue;
    }
    const slices = parseLoadCommands(r.stdout);
    if (slices.length === 0) unreadable.push(t.rel);
    else analyzed.push({ target: t, slices });
  }

  const roleCount = (role: MachoRole): number => analyzed.filter((a) => a.target.role === role).length;
  const parts: string[] = [];
  const execs = roleCount("main") + roleCount("helper-executable");
  if (execs > 0) parts.push(`${execs} executable${execs === 1 ? "" : "s"}`);
  if (roleCount("framework") > 0) parts.push(`${roleCount("framework")} framework binar${roleCount("framework") === 1 ? "y" : "ies"}`);
  if (roleCount("node") > 0) parts.push(`${roleCount("node")} .node`);
  if (roleCount("dylib") > 0) parts.push(`${roleCount("dylib")} .dylib`);
  if (roleCount("other") > 0) parts.push(`${roleCount("other")} other`);
  ctx.collector.add({
    id: "native.inventory",
    group: N,
    status: "info",
    detail: `${analyzed.length} Mach-O image(s) analyzed (${parts.join(", ") || "none"}); load commands read per architecture slice.`,
    evidence: analyzed
      .filter((a) => a.target.role === "node" || a.target.role === "dylib")
      .slice(0, 6)
      .map((a) => a.target.rel),
  });

  const gaps: string[] = [];
  if (inv.notAnalyzed > 0) gaps.push(`${inv.notAnalyzed} further Mach-O image(s) beyond the ${MAX_MACHO_ANALYZED}-file cap were not analyzed`);
  if (unreadable.length > 0) gaps.push(`${unreadable.length} could not be read by otool${tooling !== undefined ? ` (${tooling})` : ""}`);
  if (app.walk.capped) gaps.push("the bundle walk hit its entry cap, so some files were never listed");
  if (gaps.length > 0) {
    ctx.collector.add(unknown("native.coverage", N, `Native analysis is incomplete: ${gaps.join("; ")}.`, unreadable.slice(0, 6), "Re-run on a smaller bundle or raise --timeout-sec; unanalyzed images are unknown, not clean."));
  }
  if (inv.nonMachoNative > 0) {
    ctx.collector.add({
      id: "native.foreign-payloads",
      group: N,
      status: "unknown",
      detail: `${inv.nonMachoNative} .node/.dylib file(s) have unrecognized or unreadable Mach-O headers; foreign or malformed payloads were not load-checked.`,
    });
  }

  // Executable contexts for @executable_path / @rpath resolution.
  const executables: ExecutableContext[] = [];
  for (const a of analyzed) {
    if (a.target.role !== "main" && a.target.role !== "helper-executable") continue;
    for (const slice of a.slices) executables.push({ path: a.target.abs, arch: slice.arch, dir: dirname(a.target.abs), rpaths: slice.rpaths });
  }
  const nameIndex = new Map<string, string>();
  for (const e of app.walk.entries) {
    if (e.kind === "dir") continue;
    const n = basename(e.abs);
    if (!nameIndex.has(n)) nameIndex.set(n, e.rel);
  }

  const hostPaths = new Map<string, Problem>();
  const absoluteOther = new Map<string, Problem>();
  const relativeNames = new Map<string, Problem>();
  const missingLocal = new Map<string, Problem>();
  const rpathElsewhere = new Map<string, Problem>();
  const rpathMissing = new Map<string, Problem>();
  const minOsTooHigh: string[] = [];
  const wrongPlatform: string[] = [];
  let deps = 0;
  let optionalUnresolved = 0;
  let highestMinos: { v: string; rel: string } | undefined;

  const appMin = app.infoPlist.dict !== undefined ? getString(app.infoPlist.dict, "LSMinimumSystemVersion") : undefined;

  for (const a of analyzed) {
    const isExec = a.target.role === "main" || a.target.role === "helper-executable";
    for (const slice of a.slices) {
      const arch = slice.arch;
      const ownExec = executables.filter((e) => (!isExec || e.path === a.target.abs) && (e.arch === arch || e.arch === "" || arch === ""));
      if (slice.platform !== undefined && !isMacLoadablePlatform(slice.platform)) {
        wrongPlatform.push(`${a.target.rel}${arch !== "" ? ` [${arch}]` : ""}: built for ${platformName(slice.platform)}`);
      } else if (slice.minos !== undefined) {
        if (highestMinos === undefined || compareVersions(slice.minos, highestMinos.v) === 1) highestMinos = { v: slice.minos, rel: a.target.rel };
        // Optional payloads can legitimately require a newer OS. Compare only
        // the main executable, and do not override per-architecture policy.
        if (a.target.role === "main" && appMin !== undefined && app.infoPlist.dict?.LSMinimumSystemVersionByArchitecture === undefined && compareVersions(slice.minos, appMin) === 1) {
          minOsTooHigh.push(`${a.target.rel}${arch !== "" ? ` [${arch}]` : ""}: minos ${slice.minos} > LSMinimumSystemVersion ${appMin}`);
        }
      }
      for (const dep of slice.deps) {
        deps += 1;
        const v = resolveDependency(dep.name, {
          modulePath: a.target.abs,
          moduleRpaths: slice.rpaths,
          executables: ownExec,
          nameIndex,
          exists: (p) => {
            const real = app.bundleReal === undefined ? undefined : containedRealPath(app.bundleReal, p);
            if (real === undefined) return false;
            try { return statSync(real).isFile(); } catch { return false; }
          },
        });
        switch (v.kind) {
          case "system":
          case "bundled":
            break;
          case "host-path":
            noteProblem(hostPaths, a.target.rel, arch, dep.name, dep.cmd);
            break;
          case "absolute-other":
            noteProblem(absoluteOther, a.target.rel, arch, dep.name, dep.cmd);
            break;
          case "relative":
            noteProblem(relativeNames, a.target.rel, arch, dep.name, dep.cmd);
            break;
          case "missing":
            if (isOptional(dep.cmd)) {
              optionalUnresolved += 1;
            } else if (v.via === "rpath") {
              noteProblem(v.elsewhere !== undefined ? rpathElsewhere : rpathMissing, a.target.rel, arch, dep.name, dep.cmd, v.elsewhere);
            } else {
              noteProblem(missingLocal, a.target.rel, arch, dep.name, dep.cmd, v.elsewhere);
            }
            break;
        }
      }
    }
  }

  const emit = (id: string, map: Map<string, Problem>, detail: (n: number) => string, hint: string): void => {
    if (map.size === 0) return;
    const f = warn(id, N, detail(map.size), [...map.values()].slice(0, 8).map(formatProblem), hint);
    ctx.collector.add({ ...f, basis: "inferred" });
  };

  emit(
    "native.host-paths",
    hostPaths,
    (n) => `${n} load command(s) name build-host paths (/Users, /opt, /usr/local, …) — present on the build machine, usually absent on customer Macs.`,
    "Rebuild native modules so every dependency is embedded in the bundle, a system library, or @rpath/@loader_path-relative.",
  );
  emit(
    "native.missing-targets",
    missingLocal,
    (n) => `${n} @loader_path/@executable_path dependency(ies) have no confined regular-file candidate in the inspected bundle. Static inference; the actual loading process is unknown.`,
    "Ship the missing library at that relative location, or relink the module.",
  );
  emit(
    "native.absolute-targets",
    absoluteOther,
    (n) => `${n} absolute dependency path(s) outside the modeled /System/Library and /usr/lib roots; availability on other Macs is unproved.`,
    "Embed the library in the bundle and reference it with @rpath or @loader_path.",
  );
  emit(
    "native.relative-targets",
    relativeNames,
    (n) => `${n} dependency name(s) are bare or relative paths; dyld resolves them against the process working directory and fallback paths, not the bundle.`,
    "Relink with an @rpath/ or @loader_path/ install name (install_name_tool is a build-time fix, not something ShipCheck does).",
  );
  emit(
    "native.rpath-search-path",
    rpathElsewhere,
    (n) => `${n} @rpath dependency(ies) have no candidate on the modeled image/executable LC_RPATH paths, although a same-named entry exists elsewhere. Intermediate loaders may contribute additional runpaths.`,
    "Add an LC_RPATH that reaches the library, or move it to a declared location. Static inference; confirm on a clean Mac.",
  );
  emit(
    "native.rpath-missing",
    rpathMissing,
    (n) => `${n} @rpath dependency(ies) have no confined regular-file candidate on modeled image/executable LC_RPATH paths; intermediate-loader paths are unknown.`,
    "Ship the matching dylib/framework inside the bundle. Static inference; confirm on a clean Mac.",
  );

  if (minOsTooHigh.length > 0) {
    ctx.collector.add(
      warn(
        "native.min-os",
        N,
        `${minOsTooHigh.length} main executable slice(s) declare a deployment target above LSMinimumSystemVersion ${appMin}.`,
        minOsTooHigh.slice(0, 8),
        "Reconcile the main executable deployment target with the app's declared minimum OS and per-architecture policy.",
      ),
    );
  } else if (highestMinos !== undefined) {
    ctx.collector.add({
      id: "native.min-os",
      group: N,
      status: "info",
      detail: `Highest observed deployment target: ${highestMinos.v} (${highestMinos.rel}). Optional code and per-architecture OS policy prevent a bundle-wide compatibility verdict.`,
    });
  }
  if (wrongPlatform.length > 0) {
    ctx.collector.add({ id: "native.platform", group: N, status: "info", detail: `${wrongPlatform.length} image slice(s) declare another Apple platform; optional foreign payloads do not establish a macOS defect.`, evidence: wrongPlatform.slice(0, 8) });
  }

  const flagged = hostPaths.size + missingLocal.size + absoluteOther.size + relativeNames.size + rpathElsewhere.size + rpathMissing.size;
  if (flagged === 0) {
    ctx.collector.add({
      id: "native.load-targets",
      group: N,
      status: "info",
      basis: "inferred",
      detail:
        `${deps} dependency load command(s) across ${analyzed.length} image(s): no suspect required targets detected by the static path model` +
        (optionalUnresolved > 0 ? ` (${optionalUnresolved} weak dependency(ies) unresolved and ignored)` : "") +
        (gaps.length > 0 ? "; coverage is incomplete (see native.coverage)." : ". File presence is not loadability: architecture, intermediate runpaths, dlopen and Electron ABI remain unproved."),
    });
  }
}
