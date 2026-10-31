// Lipo/bin-arch probing and native-module loader classification.
//
// otool -L shape captured on macOS 27:
//   "<path>\n\t<dep> (compatibility version 5.0.0, current version 6.0.0)..."
//   Loader targets classify as: bundled, system, rpath-ish, relative,
//   host-path (a real release killer when it points at a dev machine).

import { basename, dirname, join } from "node:path";
import { existsSync, lstatSync, readdirSync } from "node:fs";
import { runTool, type ToolParams } from "./proc.js";
import { parseFileArchOutput, parseLipoInfo } from "./arch.js";

export interface ArchResult {
  archs: string[];
  universal: boolean;
  source: "lipo" | "file" | "none";
}

export function fileArch(path: string, params: ToolParams): ArchResult {
  const r = runTool("lipo", ["-info", path], params);
  if (r.code === 0) {
    const archs = parseLipoInfo(r.stdout + "\n" + r.stderr);
    if (archs.length > 0) {
      return { archs, universal: archs.length > 1, source: "lipo" };
    }
  }
  const f = runTool("file", ["-b", path], params);
  if (f.code === 0) {
    const line = f.stdout.trim();
    const archs = parseFileArchOutput(line);
    if (archs.length > 0) {
      return { archs, universal: archs.length > 1, source: "file" };
    }
  }
  return { archs: [], universal: false, source: "none" };
}

export type DepClass = "system" | "rpath" | "relative" | "host-path" | "unknown";

export interface DepEntry {
  target: string;
  cls: DepClass;
}

export interface OtoolDeps {
  entries: DepEntry[];
  rpaths: string[] | undefined;
}

export function classifyDep(target: string): DepClass {
  if (target.startsWith("@rpath") || target.startsWith("@loader_path") || target.startsWith("@executable_path")) return "rpath";
  if (!target.startsWith("/")) return "relative";
  if (target.startsWith("/System/") || target.startsWith("/usr/lib/")) return "system";
  const hostRoots = ["/Users/", "/home/", "/root/", "/tmp/", "/private/tmp/", "/private/var/folders/", "/usr/local/", "/opt/"];
  if (hostRoots.some((p) => target.startsWith(p))) return "host-path";
  return "unknown";
}

export function parseOtoolL(stdout: string): OtoolDeps {
  const lines = stdout.split("\n").map((l) => l.trim());
  const entries: DepEntry[] = [];
  for (const line of lines.slice(1)) {
    if (line.length === 0) continue;
    const target = splitLoadTarget(line);
    if (target) entries.push({ target, cls: classifyDep(target) });
  }
  return { entries, rpaths: parseRpaths(stdout) };
}

export function splitLoadTarget(line: string): string | undefined {
  const cut = line.indexOf(" (compatibility version");
  if (cut !== -1) return line.slice(0, cut).trim();
  const cut2 = line.indexOf(" (current version");
  if (cut2 !== -1) return line.slice(0, cut2).trim();
  return undefined;
}

export function parseRpaths(otoolLText: string): string[] {
  // rpaths only appear in `otool -l`; tolerate absence here.
  const found: string[] = [];
  for (const m of otoolLText.matchAll(/^\s*path\s(\S+)\s\(origin/gm)) {
    found.push(m[1] ?? "");
  }
  return found;
}

export function otoolDeps(path: string, params: ToolParams): OtoolDeps {
  const r = runTool("otool", ["-L", path], params);
  if (r.code !== 0) return { entries: [], rpaths: undefined };
  return parseOtoolL(r.stdout);
}

export function loaderTargetExistsOnDisk(target: string, modulePath: string): boolean | undefined {
  if (target.startsWith("@")) return undefined; // rpath-family: runtime-dependent
  if (target.startsWith("/")) return existsSync(target);
  const abs = join(dirname(modulePath), target);
  return existsSync(abs);
}

/** True when a dylib/framework of the same base name exists anywhere in the bundle. */
export function rpathCandidateExists(depPath: string, bundlePath: string): boolean {
  if (!depPath.startsWith("@rpath/")) return false;
  const base = basename(depPath.slice("@rpath/".length));
  const hits = searchFor(base, bundlePath, 6);
  return hits.length > 0;
}

function searchFor(base: string, bundlePath: string, maxDepth: number): string[] {
  const hits: string[] = [];
  const visit = (dir: string, depth: number): void => {
    if (depth > maxDepth || hits.length > 5) return;
    let list: string[];
    try {
      list = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of list) {
      const p = join(dir, name);
      let st;
      try {
        st = lstatSync(p);
      } catch {
        continue;
      }
      // For candidate-existence purposes symlinks count (frameworks commonly
      // alias the unversioned name to the versioned dylib) — we just never
      // follow them as directories.
      if (st.isSymbolicLink()) {
        if (name === base) hits.push(p);
        continue;
      }
      if (st.isDirectory()) visit(p, depth + 1);
      else if (name === base) hits.push(p);
    }
  };
  visit(bundlePath, 0);
  return hits;
}
