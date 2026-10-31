// Mach-O load-command analysis (static, read-only).
//
// Everything here works from `otool -arch all -l` text and plain filesystem
// existence checks. Nothing is loaded or executed. dyld's search rules are
// modelled only as far as they can be known from the bundle on disk:
//
//   @loader_path/X     relative to the directory of the image that names it
//   @executable_path/X relative to the process executable. Which process loads
//                      a framework is not knowable statically, so every
//                      executable directory in the bundle is a candidate
//   @rpath/X           searched through the image's own LC_RPATH entries and the
//                      LC_RPATH entries of the process executable
//   absolute           taken literally; /System and /usr/lib are system paths
//
// Intermediate loaders can add runpaths; the loading process is not known.
// Results describe candidate paths, never runtime loadability. Only weak
// dependencies are treated as optional; lazy dependencies are still inspected.

import { closeSync, constants, openSync, readSync } from "node:fs";
import { basename, dirname, join, posix } from "node:path";

export type DepCommand = "LC_LOAD_DYLIB" | "LC_LOAD_WEAK_DYLIB" | "LC_REEXPORT_DYLIB" | "LC_LOAD_UPWARD_DYLIB" | "LC_LAZY_LOAD_DYLIB";

const DEP_COMMANDS: ReadonlySet<string> = new Set<DepCommand>([
  "LC_LOAD_DYLIB",
  "LC_LOAD_WEAK_DYLIB",
  "LC_REEXPORT_DYLIB",
  "LC_LOAD_UPWARD_DYLIB",
  "LC_LAZY_LOAD_DYLIB",
]);

export interface MachoDep {
  cmd: DepCommand;
  name: string;
}

export interface MachoSlice {
  /** "" for a thin file (otool prints no architecture label). */
  arch: string;
  /** LC_ID_DYLIB install name (dylibs only). Not a dependency. */
  id?: string;
  deps: MachoDep[];
  rpaths: string[];
  /** Deployment target, e.g. "14.0". */
  minos?: string;
  /** LC_BUILD_VERSION platform number (1 = macOS) or 1 for LC_VERSION_MIN_MACOSX. */
  platform?: number;
}

const PLATFORM_NAMES: Record<number, string> = {
  1: "macOS",
  2: "iOS",
  3: "tvOS",
  4: "watchOS",
  5: "bridgeOS",
  6: "Mac Catalyst",
  7: "iOS Simulator",
  8: "tvOS Simulator",
  9: "watchOS Simulator",
  10: "DriverKit",
  11: "visionOS",
  12: "visionOS Simulator",
};

const PLATFORM_BY_NAME: Record<string, number> = {
  MACOS: 1,
  IOS: 2,
  TVOS: 3,
  WATCHOS: 4,
  BRIDGEOS: 5,
  MACCATALYST: 6,
  IOSSIMULATOR: 7,
  TVOSSIMULATOR: 8,
  WATCHOSSIMULATOR: 9,
  DRIVERKIT: 10,
  XROS: 11,
  VISIONOS: 11,
  XROSSIMULATOR: 12,
  VISIONOSSIMULATOR: 12,
};

export function platformName(p: number): string {
  return PLATFORM_NAMES[p] ?? `platform ${p}`;
}

/** Platforms a macOS app bundle can legitimately load code for. */
export function isMacLoadablePlatform(p: number): boolean {
  return p === 1 || p === 6 || p === 10;
}

const VERSION_MIN_PLATFORM: Record<string, number> = {
  LC_VERSION_MIN_MACOSX: 1,
  LC_VERSION_MIN_IPHONEOS: 2,
  LC_VERSION_MIN_TVOS: 3,
  LC_VERSION_MIN_WATCHOS: 4,
};

/**
 * Parse `otool [-arch all] -l` output into one record per architecture slice.
 * Tolerant by design: unknown commands are skipped, and a thin file yields one
 * slice with arch "".
 */
export function parseLoadCommands(text: string): MachoSlice[] {
  const slices: MachoSlice[] = [];
  let cur: MachoSlice | undefined;
  let cmd: string | undefined;
  let sawVersion = false;

  const ensure = (): MachoSlice => {
    if (cur === undefined) {
      cur = { arch: "", deps: [], rpaths: [] };
      slices.push(cur);
    }
    return cur;
  };

  for (const line of text.split("\n")) {
    if (line.length === 0) continue;
    if (!/^\s/.test(line)) {
      if (/^Load command \d+/.test(line)) {
        cmd = undefined;
        sawVersion = false;
        continue;
      }
      if (line.startsWith("Mach header")) continue;
      if (line.endsWith(":")) {
        const m = /\(architecture ([^)]+)\):$/.exec(line);
        cur = { arch: m?.[1] ?? "", deps: [], rpaths: [] };
        slices.push(cur);
        cmd = undefined;
        continue;
      }
    }
    const cm = /^\s*cmd (LC_\w+)\s*$/.exec(line);
    if (cm !== null) {
      cmd = cm[1];
      sawVersion = false;
      const platform = cmd !== undefined ? VERSION_MIN_PLATFORM[cmd] : undefined;
      if (platform !== undefined) ensure().platform = platform;
      continue;
    }
    if (cmd === undefined) continue;
    const s = ensure();
    if (DEP_COMMANDS.has(cmd) || cmd === "LC_ID_DYLIB") {
      const nm = /^\s+name (.+) \(offset \d+\)\s*$/.exec(line);
      if (nm !== null && nm[1] !== undefined) {
        if (cmd === "LC_ID_DYLIB") s.id = nm[1];
        else s.deps.push({ cmd: cmd as DepCommand, name: nm[1] });
      }
    } else if (cmd === "LC_RPATH") {
      const pm = /^\s+path (.+) \(offset \d+\)\s*$/.exec(line);
      if (pm !== null && pm[1] !== undefined) s.rpaths.push(pm[1]);
    } else if (cmd === "LC_BUILD_VERSION") {
      const mm = /^\s+minos (\S+)\s*$/.exec(line);
      if (mm !== null && mm[1] !== undefined) s.minos = mm[1];
      const pf = /^\s+platform (\S+)\s*$/.exec(line);
      if (pf !== null && pf[1] !== undefined) {
        const n = /^\d+$/.test(pf[1]) ? Number(pf[1]) : PLATFORM_BY_NAME[pf[1].toUpperCase()];
        if (n !== undefined) s.platform = n;
      }
    } else if (VERSION_MIN_PLATFORM[cmd] !== undefined) {
      const vm = /^\s+version (\S+)\s*$/.exec(line);
      if (vm !== null && vm[1] !== undefined && !sawVersion) {
        sawVersion = true;
        s.minos = vm[1];
      }
    }
  }
  return slices.filter((s) => s.deps.length > 0 || s.rpaths.length > 0 || s.id !== undefined || s.minos !== undefined || s.platform !== undefined || s.arch !== "");
}

/** Compare dotted numeric versions ("14.0", "10.13.6"). Returns undefined when either is malformed. */
export function compareVersions(a: string, b: string): number | undefined {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (pa === undefined || pb === undefined) return undefined;
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

function parseVersion(v: string): number[] | undefined {
  const t = v.trim();
  if (!/^\d+(\.\d+){0,3}$/.test(t)) return undefined;
  return t.split(".").map(Number);
}

// ---- dependency resolution ----------------------------------------------------------

export type DepVerdict =
  | { kind: "system" }
  | { kind: "bundled"; resolved: string }
  | { kind: "host-path" }
  | { kind: "absolute-other" }
  | { kind: "relative" }
  | { kind: "missing"; via: "loader_path" | "executable_path" | "rpath"; /** same file name exists elsewhere in the bundle (bundle-relative) */ elsewhere?: string };

const HOST_ROOTS = [
  "/Users/",
  "/home/",
  "/root/",
  "/tmp/",
  "/private/",
  "/usr/local/",
  "/opt/",
  "/Volumes/",
  "/nix/",
  "/Library/Developer/",
  "/Applications/Xcode",
];

export interface ExecutableContext {
  /** Exact executable, kept separate even when helpers share a directory. */
  path?: string;
  arch?: string;
  /** Directory holding the process executable (Contents/MacOS of the main app or a helper app). */
  dir: string;
  /** LC_RPATH entries of that executable (unexpanded). */
  rpaths: string[];
}

export interface ResolveInput {
  /** Absolute path of the image that names the dependency. */
  modulePath: string;
  /** LC_RPATH entries of that image's slice (unexpanded). */
  moduleRpaths: string[];
  /** Candidate process executables that could load it. */
  executables: ExecutableContext[];
  /** Existence check (injected so tests need no files). */
  exists?: (p: string) => boolean;
  /** Bundle-relative paths by file name, for "present but not on a search path" hints. */
  nameIndex?: ReadonlyMap<string, string>;
}

function expandRpath(rp: string, loaderDir: string, execDir: string): string | undefined {
  if (rp === "@loader_path" || rp.startsWith("@loader_path/")) return join(loaderDir, rp.slice("@loader_path".length));
  if (rp === "@executable_path" || rp.startsWith("@executable_path/")) return join(execDir, rp.slice("@executable_path".length));
  if (rp.startsWith("/")) return rp;
  return undefined; // relative LC_RPATH entries have no stable meaning
}

export function resolveDependency(name: string, input: ResolveInput): DepVerdict {
  // Callers must supply a bundle-confined regular-file lookup. Never inspect
  // arbitrary host paths named by an untrusted load command.
  const exists = input.exists ?? (() => false);
  const loaderDir = dirname(input.modulePath);
  const hint = (): string | undefined => input.nameIndex?.get(basename(name));

  if (name.startsWith("@loader_path/")) {
    const p = join(loaderDir, name.slice("@loader_path".length));
    return exists(p) ? { kind: "bundled", resolved: p } : { kind: "missing", via: "loader_path", elsewhere: hint() };
  }
  if (name.startsWith("@executable_path/")) {
    for (const e of input.executables) {
      const p = join(e.dir, name.slice("@executable_path".length));
      if (exists(p)) return { kind: "bundled", resolved: p };
    }
    return { kind: "missing", via: "executable_path", elsewhere: hint() };
  }
  if (name.startsWith("@rpath/")) {
    const rest = name.slice("@rpath/".length);
    const execs = input.executables.length > 0 ? input.executables : [{ dir: loaderDir, rpaths: [] }];
    for (const e of execs) {
      const roots = [
        ...input.moduleRpaths.map((r) => expandRpath(r, loaderDir, e.dir)),
        ...e.rpaths.map((r) => expandRpath(r, e.dir, e.dir)),
      ];
      for (const root of roots) {
        if (root === undefined) continue;
        const p = join(root, rest);
        if (exists(p)) return { kind: "bundled", resolved: p };
      }
    }
    return { kind: "missing", via: "rpath", elsewhere: hint() };
  }
  if (name.startsWith("@")) return { kind: "relative" }; // unknown @-variable: treat as unverifiable
  const absolute = name.startsWith("/") ? posix.normalize(name) : name;
  if (absolute.startsWith("/System/Library/") || absolute.startsWith("/usr/lib/")) return { kind: "system" };
  if (name.startsWith("/")) {
    return HOST_ROOTS.some((r) => absolute.startsWith(r)) ? { kind: "host-path" } : { kind: "absolute-other" };
  }
  return { kind: "relative" };
}

// ---- Mach-O detection -----------------------------------------------------------------

const THIN_MAGICS = new Set([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe]);

/** Cheap magic-number test. Reads at most 8 bytes; never follows a path the caller has not vetted. */
export function isMachOFile(path: string): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const buf = Buffer.alloc(8);
    const n = readSync(fd, buf, 0, 8, 0);
    if (n < 8) return false;
    const be = buf.readUInt32BE(0);
    if (THIN_MAGICS.has(be)) return true;
    if (be === 0xcafebabe || be === 0xcafebabf) {
      // Java class files share 0xCAFEBABE; a fat header's next word is a small arch count.
      return buf.readUInt32BE(4) > 0 && buf.readUInt32BE(4) < 20;
    }
    if (be === 0xbebafeca || be === 0xbfbafeca) return buf.readUInt32LE(4) > 0 && buf.readUInt32LE(4) < 20;
    return false;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
