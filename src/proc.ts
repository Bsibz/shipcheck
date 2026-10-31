// System-tool process runner. Everything shipcheck learns from the host comes
// through this module: sync spawns of small macOS command-line tools, with a
// timeout and a bounded buffer. No shell interpolation, ever — arguments are
// passed as an argv array.
//
// Trust boundary: tools are NEVER looked up through PATH. `npm run`/`npx` put
// node_modules/.bin first on PATH, so a bare-name spawn would let any
// dependency impersonate codesign and mint a "verified" signing section. Each
// tool maps to one absolute system path, runs with a minimal environment
// (no DEVELOPER_DIR, no DYLD_*, no inherited PATH), and the resolved paths are
// recorded in the report's provenance block.
//
// Read-only policy: this module spawns whitelisted Apple tools on target paths
// and never writes to the target. Mutating commands are structurally
// impossible by construction here (no write-capable tool is invoked).

import { spawnSync } from "node:child_process";
import { accessSync, constants, lstatSync } from "node:fs";
import { isAbsolute } from "node:path";

export interface ToolResult {
  /** Exit code, or -1 when the tool did not run to a normal exit. */
  code: number;
  stdout: string;
  stderr: string;
  /**
   * ok: the process ran and exited (any exit code — judge `code`).
   * timeout / missing / error: the tool produced NO usable verdict; callers
   * must report unknown, never a product defect.
   */
  status: "ok" | "timeout" | "missing" | "error";
  timedOut: boolean;
  /** Spawn error code when status is not "ok" (ETIMEDOUT, ENOENT, ENOBUFS, …). */
  errorCode?: string;
  /** Set for status "missing" (kept for older callers). */
  notFound?: string;
}

export interface ToolParams {
  timeoutMs: number;
}

interface ToolSpec {
  path: string;
  /** Arguments always placed before the caller's (e.g. xcrun's tool name). */
  prefix: readonly string[];
}

const DEFAULT_TOOLS: Readonly<Record<string, ToolSpec>> = {
  codesign: { path: "/usr/bin/codesign", prefix: [] },
  spctl: { path: "/usr/sbin/spctl", prefix: [] },
  xattr: { path: "/usr/bin/xattr", prefix: [] },
  file: { path: "/usr/bin/file", prefix: [] },
  otool: { path: "/usr/bin/otool", prefix: [] },
  lipo: { path: "/usr/bin/lipo", prefix: [] },
  plutil: { path: "/usr/bin/plutil", prefix: [] },
  stapler: { path: "/usr/bin/xcrun", prefix: ["stapler"] },
  // Fixed non-mounting inspection route. No caller-supplied verbs/options.
  "dmg-info": { path: "/usr/bin/hdiutil", prefix: ["imageinfo", "-plist", "-stdinpass"] },
};

/** Test seam only (not reachable from the CLI): swap a tool for a fixture binary. */
const overrides = new Map<string, ToolSpec>();
export function setToolOverride(tool: string, spec: { path: string; prefix?: readonly string[] } | undefined): void {
  if (spec === undefined) overrides.delete(tool);
  else overrides.set(tool, { path: spec.path, prefix: spec.prefix ?? [] });
}

const used = new Map<string, string>();

function specFor(tool: string): ToolSpec {
  const spec = overrides.get(tool) ?? DEFAULT_TOOLS[tool];
  if (spec === undefined) throw new Error(`shipcheck: "${tool}" is not an allowed host tool`);
  return spec;
}

export function toolPath(tool: string): string {
  return specFor(tool).path;
}

/** Tools actually invoked this run → absolute path (for the provenance block). */
export function usedToolPaths(): Record<string, string> {
  return Object.fromEntries([...used.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

export function toolExists(tool: string): boolean {
  try {
    accessSync(specFor(tool).path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** The tools an audit needs, so a missing one can be reported once at startup (exit 4). */
export function missingTools(tools: readonly string[]): string[] {
  return tools.filter((t) => !toolExists(t)).map((t) => `${t} (${toolPath(t)})`);
}

const TOOL_ENV_DESCRIPTION = "minimal env: PATH=/usr/bin:/bin:/usr/sbin:/sbin; DEVELOPER_DIR, DYLD_* and the rest of the parent environment are not passed";

export function toolEnvironmentNote(): string {
  return TOOL_ENV_DESCRIPTION;
}

function minimalEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    LANG: "en_US.UTF-8",
  };
  if (process.env["HOME"] !== undefined) env["HOME"] = process.env["HOME"];
  if (process.env["TMPDIR"] !== undefined) env["TMPDIR"] = process.env["TMPDIR"];
  return env;
}

export function runTool(
  tool: string,
  args: readonly string[],
  params: ToolParams,
  maxStdoutKiB = 32 * 1024,
): ToolResult {
  if (tool === "dmg-info") {
    let safe = false;
    try { safe = args.length === 1 && isAbsolute(args[0]!) && lstatSync(args[0]!).isFile(); } catch { /* refuse */ }
    if (!safe) return { code: -1, stdout: "", stderr: "", status: "error", timedOut: false, errorCode: "UNSAFE_DMG_ARGS" };
  }
  const spec = specFor(tool);
  used.set(tool, spec.path);
  const r = spawnSync(spec.path, [...spec.prefix, ...args], {
    encoding: "utf8",
    timeout: params.timeoutMs,
    maxBuffer: maxStdoutKiB * 1024,
    windowsHide: true,
    env: minimalEnv(),
  });
  if (r.error) {
    const errorCode = (r.error as NodeJS.ErrnoException).code ?? "error";
    if (errorCode === "ENOENT" || errorCode === "EACCES") {
      return { code: -1, stdout: "", stderr: "", status: "missing", timedOut: false, errorCode, notFound: errorCode };
    }
    if (errorCode === "ETIMEDOUT") {
      return { code: -2, stdout: "", stderr: "", status: "timeout", timedOut: true, errorCode };
    }
    // ENOBUFS (output over maxBuffer) and anything else: no trustworthy output.
    return { code: -1, stdout: "", stderr: "", status: "error", timedOut: false, errorCode };
  }
  if (r.status === null) {
    // Killed by a signal we did not request (crash): no exit code, no verdict.
    return { code: -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: "error", timedOut: false, errorCode: r.signal ?? "signal" };
  }
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: "ok", timedOut: false };
}

/** Read stdout/stderr while also keeping code for exit-driven logic. */
export function combined(result: ToolResult): string {
  return (result.stdout + "\n" + result.stderr).trim();
}

/** Lines of tool output, trimmed, dropping empties. */
export function lines(result: ToolResult): string[] {
  return combined(result)
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}
