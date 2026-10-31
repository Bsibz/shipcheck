// Architecture checks: main executable, helper executables, framework
// binaries, native modules — and whether each can actually load under the
// architectures the main binary supports (the #1 class of "works on my
// Intel, dies on my Apple Silicon" release failure).

import { existsSync, readdirSync, statSync } from "node:fs";
import type { AuditContext } from "./checkscommon.js";
import { GROUP, fail, info, warn } from "./checkscommon.js";
import { fileArch } from "./native.js";
import type { AppStructure } from "./bundle.js";

const A = GROUP.arch;

export interface ArchFacts {
  main: string[];
  universal: boolean;
}

export function runArchitecture(ctx: AuditContext): ArchFacts | undefined {
  const app = ctx.app;
  if (app === undefined) return undefined;

  if (app.execPath === undefined || !existsSync(app.execPath)) {
    ctx.collector.add(fail("arch.main", A, "Main executable missing; architecture unknown."));
    return undefined;
  }
  const main = fileArch(app.execPath, ctx.params);
  if (main.source === "none") {
    ctx.collector.add({
      id: "arch.main",
      group: A,
      status: "unknown",
      detail: "Could not determine main executable architecture (lipo AND file failed).",
      evidence: [app.execPath],
    });
    return undefined;
  }
  ctx.collector.add({
    id: "arch.main",
    group: A,
    status: main.universal ? "pass" : "info",
    detail: `Main executable: ${main.universal ? "universal (" : "single arch ("}${main.archs.join(" + ")})${main.universal ? "" : " — runs only where that arch is supported"}.`,
    evidence: [app.execPath],
  });
  if (ctx.opts.universal && !main.universal) {
    ctx.collector.add({
      id: "arch.universal-required",
      group: A,
      status: "fail",
      detail: `Release policy requires a universal binary; main executable is ${main.archs.join("")}.`,
      hint: "Build both archs into one slice (lipo or one Xcode UM build).",
    });
  }

  const supported = new Set(main.archs);
  const supportsArm = [...supported].some((a) => a.startsWith("arm64"));
  const supportsIntel = [...supported].some((a) => a.startsWith("x86"));

  // native modules: each must load under one of the app's archs — except
  // cross-platform prebuild slices (node-gyp "prebuilds/<platform>-<arch>/"
  // trees bundle linux/android/win binaries INSIDE mac bundles on purpose;
  // observed live in ChatGPT.app's app.asar.unpacked). Only mac slices of
  // those trees get parity checks; foreign slices are evidence, and a tree
  // with NO mac slice is the real defect the old naive check was reaching for.
  const problems: string[] = [];
  const foreignByTree = new Map<string, number>();
  const treeOf: Array<{ rel: string; treeRoot: string; tokens: string[] }> = [];
  let okModules = 0;
  let checked = 0;
  for (const mod of app.nativeModules) {
    const prebuildSlice = prebuildDirToken(mod.abs);
    if (prebuildSlice !== undefined && !isMacSliceToken(prebuildSlice.slice)) {
      if (recognizedNonMacPlatform(prebuildSlice.slice)) {
        const treeRoot = mod.abs.slice(0, prebuildSlice.index + "/prebuilds".length);
        foreignByTree.set(treeRoot, (foreignByTree.get(treeRoot) ?? 0) + 1);
        continue; // foreign-platform slice: never a mac parity failure
      }
      // unrecognized token: still probed below (conservative)
    } else if (prebuildSlice !== undefined) {
      treeOf.push({ rel: mod.rel, treeRoot: mod.abs.slice(0, prebuildSlice.index + "/prebuilds".length), tokens: readdirNames(mod.abs.slice(0, prebuildSlice.index + "/prebuilds".length)) });
    }
    checked += 1;
    const archs = fileArch(mod.abs, ctx.params);
    if (archs.source === "none") {
      problems.push(`${mod.rel}: unreadable/not a Mach-O`);
      continue;
    }
    const loadable = [...archs.archs].some((a) => meaningfulArch(a) && supported.has(meaningfulArch(a)));
    if (!loadable) {
      problems.push(
        `${mod.rel}: module arch ${archs.archs.join("·")} not loadable by app arch ${[...supported].join("·")}`,
      );
    } else {
      okModules += 1;
    }
  }
  const foreignTotal = [...foreignByTree.values()].reduce((a, b) => a + b, 0);
  // prebuild trees with no mac-compatible slice at all: require() falls back
  // to source builds or dies at startup — flag, softly.
  const maclessTrees = uniqueStr(treeOf).filter((t) => !t.tokens.some(isMacSliceToken));
  if (app.nativeModules.length === 0) {
    ctx.collector.add(info("arch.native-modules", A, "No .node/.dylib payloads in the bundle (pure-JS release)."));
  } else if (problems.length > 0) {
    ctx.collector.add({
      id: "arch.native-modules",
      group: A,
      status: "fail",
      detail: `${problems.length} of ${checked} mac-relevant native modules cannot load under the app's architectures.`,
      evidence: problems.slice(0, 6),
      hint: "Rebuild native modules for the same arch slices the app supports; ship both slices for universal apps.",
    });
  } else {
    ctx.collector.add({
      id: "arch.native-modules",
      group: A,
      status: "pass",
      detail:
        `${okModules}/${checked} mac-relevant native modules loadable under the app's architectures.` +
        (foreignTotal > 0 ? ` (+${foreignTotal} foreign-platform prebuild slice(s) present, not parity-checked.)` : ""),
    });
  }
  if (maclessTrees.length > 0) {
    ctx.collector.add(
      warn(
        "arch.native-prebuilds",
        A,
        `${maclessTrees.length} prebuild tree(s) ship no darwin/macos slice — requiring them on macOS falls back to source builds or fails at startup.`,
        maclessTrees.slice(0, 3).map((t) => `${relToBundle(app, t.treeRoot)} → ${t.tokens.join(", ") || "(empty)"}`),
        "Ship prebuilds for darwin or bundle the package's build outputs for the platform you target.",
      ),
    );
  }

  // helper + framework executables parity (soft informational)
  const helperPaths = helperExecutables(app);
  const helperMismatches: string[] = [];
  for (const p of helperPaths) {
    const archs = fileArch(p, ctx.params);
    if (archs.source === "none") {
      helperMismatches.push(`${relToBundle(app, p)}: unreadable`);
      continue;
    }
    const loadable = [...archs.archs].some((a) => meaningfulArch(a) && supported.has(meaningfulArch(a)));
    if (!loadable) helperMismatches.push(`${relToBundle(app, p)}: ${archs.archs.join("·")}`);
  }
  if (helperMismatches.length > 0) {
    ctx.collector.add(warn("arch.helpers", A, `${helperMismatches.length} helper/framework binaries have architectures the main app cannot run:`, helperMismatches.slice(0, 5), "Mixed-arch builds (e.g. arm64 main + x86_64 helpers) crash at helper launch."));
  } else if (helperPaths.length > 0) {
    ctx.collector.add(info("arch.helpers", A, `${helperPaths.length} helper/framework binary(ies) match the app's architectures.`));
  }

  void supportsArm;
  void supportsIntel;
  return { main: [...supported], universal: main.universal };
}

/** Map arch tokens from codesign/lipo to loader-arch equality tokens. */
export function meaningfulArch(a: string): string {
  const norm = a.toLowerCase().replace(/\.x1$/, "");
  if (norm === "arm64e") return "arm64"; // arm64e can host arm64 code? helper side: treat as arm64 family on this check level
  return norm;
}

// ---- cross-platform prebuild classification ---------------------------------

const PREBUILD_TOKEN = /\/prebuilds\/([^/]+)\//;

/**
 * Locate the node-gyp/prebuildify "prebuilds/<slice>/" directory token in an
 * absolute module path. Formatting verified live: ChatGPT.app ships
 * app.asar.unpacked/node_modules/<pkg>/prebuilds/{darwin-*,linux-*,android-*}/
 * node.napi.*.node — foreign slices bundled with mac builds.
 */
export function prebuildDirToken(abs: string): { slice: string; index: number } | undefined {
  const m = PREBUILD_TOKEN.exec(abs);
  return m ? { slice: m[1] ?? "", index: m.index } : undefined;
}

/** Tokens naming a mac-loadable slice (includes x64+arm64 combo dirs). */
export function isMacSliceToken(token: string): boolean {
  return /darwin|macos/i.test(token);
}

/** Platform tokens we recognize as intentionally-not-mac (never a fail). */
export function recognizedNonMacPlatform(token: string): boolean {
  return /^(linux|android|win32|windows|freebsd|openbsd|sunos|aix)/i.test(token);
}

function readdirNames(dir: string): string[] {
  try {
    return readdirSync(dir).slice(0, 32);
  } catch {
    return [];
  }
}

function uniqueStr(items: Array<{ rel: string; treeRoot: string; tokens: string[] }>): Array<{ rel: string; treeRoot: string; tokens: string[] }> {
  const seen = new Set<string>();
  const out: Array<{ rel: string; treeRoot: string; tokens: string[] }> = [];
  for (const t of items) {
    if (seen.has(t.treeRoot)) continue;
    seen.add(t.treeRoot);
    out.push(t);
  }
  return out;
}

function helperExecutables(app: AppStructure): string[] {
  const out: string[] = [];
  for (const f of app.frameworkBinaries) {
    if (existsSync(f) && statSyncFile(f)) out.push(f);
  }
  return out;
}

function statSyncFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function relToBundle(app: AppStructure, p: string): string {
  const bundlePath = app.bundlePath;
  if (p.startsWith(bundlePath)) return p.slice(bundlePath.length + 1);
  const parts = p.split("/");
  return parts[parts.length - 1] ?? p;
}
