// .app bundle structure discovery.
//
// Walks a .app bundle, classifying exactly what shipcheck's checks need:
// Info.plist + main executable, helper apps, frameworks, native modules,
// ASAR payloads, and the code signature directory. Bounded: symlinks are
// never followed, and the walk caps total entries so a pathological bundle
// cannot stall a CI run.

import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, join, sep } from "node:path";
import { asDict, getString, parsePlistXml, type PlistDict } from "./plist.js";
import { runTool } from "./proc.js";

export interface WalkCapped {
  entries: WalkedEntry[];
  capped: boolean;
  totalSeen: number;
}

export interface WalkedEntry {
  abs: string;
  rel: string;
  kind: "file" | "dir" | "symlink" | "other";
  size: number;
  /** st_mode of regular files (permission bits matter for executable detection). */
  mode?: number;
}

export function nfc(s: string): string {
  return s.normalize("NFC");
}

const MAX_ENTRIES = 40_000;

export function walkTree(rootDir: string): WalkCapped {
  const entries: WalkedEntry[] = [];
  let totalSeen = 0;
  let capped = false;

  const visit = (dir: string, rel: string): void => {
    if (capped) return;
    let names: string[];
    try {
      names = readdirSync(dir, { withFileTypes: true }).map((d) => d.name);
    } catch {
      return;
    }
    for (const name of names) {
      totalSeen += 1;
      if (totalSeen > MAX_ENTRIES) {
        capped = true;
        return;
      }
      const abs = join(dir, name);
      const relPath = rel === "" ? name : rel + "/" + name;
      let st;
      try {
        st = lstatSync(abs);
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) {
        entries.push({ abs, rel: relPath, kind: "symlink", size: 0 });
        continue; // never follow
      }
      if (st.isDirectory()) {
        entries.push({ abs, rel: relPath, kind: "dir", size: 0 });
        visit(abs, relPath);
      } else if (st.isFile()) {
        entries.push({ abs, rel: relPath, kind: "file", size: st.size, mode: st.mode });
      } else {
        entries.push({ abs, rel: relPath, kind: "other", size: 0 });
      }
    }
  };

  visit(rootDir, "");
  return { entries, capped, totalSeen };
}

/** A path (or symlink) inside the bundle that resolves outside it, or an unsafe Info.plist reference. */
export interface BundleEscape {
  /** Bundle-relative path (or plist key description). */
  rel: string;
  kind: "symlink" | "info-plist" | "executable-name" | "executable" | "framework-binary" | "resources";
  detail: string;
}

/** Real path of `p` when it exists and lies inside `rootReal`; otherwise undefined. */
export function containedRealPath(rootReal: string, p: string): string | undefined {
  let real: string;
  try {
    real = realpathSync(p);
  } catch {
    return undefined;
  }
  return real === rootReal || real.startsWith(rootReal.endsWith(sep) ? rootReal : rootReal + sep) ? real : undefined;
}

/** True when `p` exists (via lstat) and resolves inside `rootReal`. */
export function isContained(rootReal: string, p: string): boolean {
  return containedRealPath(rootReal, p) !== undefined;
}

/** CFBundleExecutable must be a single path component. */
export function isSafeExecName(name: string): boolean {
  return name.length > 0 && name !== "." && name !== ".." && !name.includes("/") && !name.includes("\\") && !name.includes("\0");
}

export interface AppStructure {
  bundlePath: string;
  /** realpath of the bundle root; every read of bundle content is confined to it. */
  bundleReal?: string;
  /** Escape attempts found while reading the bundle. Non-empty means fail closed. */
  escapes: BundleEscape[];
  bundleName: string;
  contentsDir: string;
  infoPlistPath: string;
  infoPlist: { ok: boolean; dict?: PlistDict; error?: string; /** plutil (binary plist conversion) gave no result: unknown, not "broken". */ toolUnavailable?: boolean };
  execName?: string;
  execPath?: string;
  codeSignDir?: string;
  resourcesDir?: string;
  /** Helper .app bundles (Electron helpers etc.), full paths. */
  helperApps: string[];
  /** Frameworks under Contents/Frameworks, full paths. */
  frameworks: string[];
  /** Main Mach-O binaries of frameworks (.framework/Versions/<v>/<name>). */
  frameworkBinaries: string[];
  /** Native modules: any .node or .dylib in the bundle. */
  nativeModules: Array<{ abs: string; rel: string; kind: "dylib" | "node" }>;
  asarPaths: string[];
  looseAppDir?: string;
  unpackedDir?: string;
  walk: WalkCapped;
}

export function findExecutableForFramework(frameworkDir: string, bundleReal?: string, escapes?: BundleEscape[], bundlePath?: string): string | undefined {
  // macOS framework layout: <name>.framework/Versions/<v>/<name>
  const name = basename(frameworkDir).replace(/\.framework$/, "");
  const versions = join(frameworkDir, "Versions");
  if (!existsSync(versions)) return undefined;
  let best: string | undefined;
  try {
    for (const v of readdirSync(versions)) {
      if (v === "Current") continue;
      const cand = join(versions, v, name);
      if (existsSync(cand)) {
        if (bundleReal !== undefined && !isContained(bundleReal, cand)) {
          escapes?.push({
            rel: bundlePath !== undefined ? cand.slice(bundlePath.length + 1) : cand,
            kind: "framework-binary",
            detail: "framework binary resolves outside the app bundle; not read",
          });
          continue;
        }
        if (best === undefined || cand.includes("/A/")) best = cand;
      }
    }
  } catch {
    return undefined;
  }
  return best;
}

export function readAppStructure(bundlePath: string): AppStructure {
  const contentsDir = join(bundlePath, "Contents");
  const infoPlistPath = join(contentsDir, "Info.plist");
  const bundleName = basename(bundlePath);

  const resourcesDir = join(contentsDir, "Resources");
  const codeSignDir = join(contentsDir, "_CodeSignature");

  const escapes: BundleEscape[] = [];
  let bundleReal: string | undefined;
  try {
    bundleReal = realpathSync(bundlePath);
  } catch {
    bundleReal = undefined;
  }

  const infoPlist: AppStructure["infoPlist"] = { ok: false };
  if (bundleReal === undefined) {
    infoPlist.error = "bundle root could not be resolved";
  } else if (lstatExists(infoPlistPath) && !isContained(bundleReal, infoPlistPath)) {
    infoPlist.error = "Contents/Info.plist resolves outside the app bundle; not read";
    escapes.push({ rel: "Contents/Info.plist", kind: "info-plist", detail: infoPlist.error });
  } else if (existsSync(infoPlistPath)) {
    const bytes = readFileSync(infoPlistPath);
    let raw: string | undefined;
    if (bytes.subarray(0, 6).toString("latin1") === "bplist") {
      // Many real apps (Keynote, Xcode, …) ship a binary Info.plist. plutil
      // converts to XML on stdout only; the file itself is never touched.
      const conv = runTool("plutil", ["-convert", "xml1", "-o", "-", "--", infoPlistPath], { timeoutMs: 30_000 });
      if (conv.status === "ok" && conv.code === 0) raw = conv.stdout;
      else {
        // plutil refusing the file (exit != 0) means the plist is genuinely corrupt;
        // plutil not running at all (timeout/missing) says nothing about the file.
        infoPlist.toolUnavailable = conv.status !== "ok";
        infoPlist.error = `binary Info.plist could not be converted by plutil (${conv.status === "ok" ? `exit ${conv.code}` : (conv.errorCode ?? conv.status)})`;
      }
    } else {
      raw = bytes.toString("utf8");
    }
    if (raw !== undefined) {
      const parsed = parsePlistXml(raw);
      const dict = asDict(parsed.value);
      if (parsed.ok && dict !== undefined) {
        infoPlist.ok = true;
        infoPlist.dict = dict;
      } else {
        infoPlist.error = parsed.error ?? "not a plist dict";
      }
    }
  } else {
    infoPlist.error = "missing Contents/Info.plist";
  }

  const dict = infoPlist.dict;
  const execName = dict !== undefined ? getString(dict, "CFBundleExecutable") : undefined;
  const csdir = join(contentsDir, "MacOS");
  let execPath: string | undefined;
  if (execName !== undefined) {
    if (!isSafeExecName(execName)) {
      escapes.push({
        rel: "Contents/Info.plist: CFBundleExecutable",
        kind: "executable-name",
        detail: `CFBundleExecutable is not a single file name (${JSON.stringify(execName).slice(0, 80)}); path traversal refused`,
      });
    } else {
      const cand = join(csdir, execName);
      if (bundleReal !== undefined && lstatExists(cand) && !isContained(bundleReal, cand)) {
        escapes.push({ rel: `Contents/MacOS/${execName}`, kind: "executable", detail: "main executable resolves outside the app bundle; not read or executed" });
      } else if (bundleReal !== undefined && lstatExists(csdir) && !isContained(bundleReal, csdir)) {
        escapes.push({ rel: "Contents/MacOS", kind: "executable", detail: "Contents/MacOS resolves outside the app bundle; not read" });
      } else {
        execPath = cand;
      }
    }
  }

  const walk = walkTree(bundlePath);

  const helperApps: string[] = [];
  const frameworks: string[] = [];
  const frameworkBinaries: string[] = [];
  const nativeModules: AppStructure["nativeModules"] = [];
  const asarPaths: string[] = [];
  let looseAppDir: string | undefined;
  let unpackedDir: string | undefined;

  if (bundleReal !== undefined) {
    for (const e of walk.entries) {
      if (e.kind !== "symlink") continue;
      let real: string | undefined;
      try {
        real = realpathSync(e.abs);
      } catch {
        // dangling: cannot be followed to anywhere, nothing reads it
        continue;
      }
      if (!isContained(bundleReal, real)) {
        escapes.push({ rel: e.rel, kind: "symlink", detail: `symlink resolves outside the app bundle (${real}); never followed` });
      }
    }
  }

  for (const e of walk.entries) {
    if (e.kind !== "file" && e.kind !== "dir") continue;
    const base = nfc(basename(e.abs));
    if (e.kind === "dir" && base.endsWith(".app") && e.abs !== bundlePath) {
      helperApps.push(e.abs);
    } else if (e.kind === "dir" && base.endsWith(".framework")) {
      frameworks.push(e.abs);
      const bin = findExecutableForFramework(e.abs, bundleReal, escapes, bundlePath);
      if (bin !== undefined) frameworkBinaries.push(bin);
    } else if (e.kind === "file") {
      if (base.endsWith(".node")) {
        nativeModules.push({ abs: e.abs, rel: e.rel, kind: "node" });
      } else if (base.endsWith(".dylib")) {
        nativeModules.push({ abs: e.abs, rel: e.rel, kind: "dylib" });
      } else if (base.endsWith(".asar")) {
        asarPaths.push(e.abs);
      }
    }
    if (e.kind === "dir" && e.rel === "Contents/Resources/app" && looseAppDir === undefined) {
      looseAppDir = e.abs;
    }
    if (e.kind === "dir" && nfc(e.rel) === "app.asar.unpacked" && unpackedDir === undefined) {
      unpackedDir = e.abs;
    }
  }
  if (asarPaths.length === 0 && dirExists(join(resourcesDir, "app"))) {
    looseAppDir = join(resourcesDir, "app");
  }

  return {
    bundlePath,
    bundleReal,
    escapes,
    bundleName,
    contentsDir,
    infoPlistPath,
    infoPlist,
    execName,
    execPath,
    codeSignDir: lstatDir(codeSignDir) ? codeSignDir : undefined,
    resourcesDir: lstatDir(resourcesDir) ? resourcesDir : undefined,
    helperApps,
    frameworks,
    frameworkBinaries,
    nativeModules,
    asarPaths,
    looseAppDir,
    unpackedDir,
    walk,
  };
}

function lstatExists(p: string): boolean {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

/** Real directory only: a symlinked Resources/_CodeSignature is never trusted as a directory. */
function lstatDir(p: string): boolean {
  return dirExists(p);
}

function dirExists(p: string): boolean {
  try {
    return lstatSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Find the .app bundle root at or above a path (supports passing the .app,
 *  its Contents folder, or an executable inside it). */
export function resolveAppBundle(p: string): string | undefined {
  let cur = p;
  for (let i = 0; i < 4; i += 1) {
    if (existsSync(join(cur, "Contents", "Info.plist"))) return cur;
    const parent = join(cur, "..");
    if (parent === cur) break;
    cur = parent;
  }
  return undefined;
}
