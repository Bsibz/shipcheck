// Gatekeeper facts: spctl assessment and quarantine provenance.
//
// Truth shapes (captured on macOS 27):
//   accepted → stdout "<path>: accepted" + optional source/origin lines, exit 0
//   rejected → stdout "<path>: rejected", exit 3 (no source line)
//   quarantine absent → stderr "No such xattr: com.apple.quarantine", exit 1
//
// Network note: spctl may consult Apple's cloud for some candidates, so it runs
// only under --gatekeeper (default verdict: UNKNOWN). stapler validate also
// downloads tickets and is opt-in only (--stapler).

import { runTool, type ToolParams } from "./proc.js";

export interface SpctlResult {
  assessment: "accepted" | "rejected" | "unknown";
  /** spctl printed override=… (e.g. assessments disabled): the "accepted" is not a real verdict. */
  override?: string;
  source?: string;
  origin?: string;
  exitCode: number;
  note?: string;
}

export function spctlAssess(path: string, params: ToolParams): SpctlResult {
  const r = runTool("spctl", ["-a", "-vv", "-t", "exec", path], params);
  if (r.status !== "ok") {
    return { assessment: "unknown", exitCode: r.code, note: r.status === "timeout" ? "spctl timed out" : `spctl could not run (${r.errorCode ?? r.status})` };
  }
  const out = (r.stdout + "\n" + r.stderr).trim();
  const linesOf = out.split("\n").map((l) => l.trim());
  const verdictLine = linesOf.find((l) => l.startsWith(":") === false && (l.includes("accepted") || l.includes("rejected"))) ?? "";
  if (r.code === 0 && verdictLine.includes("accepted")) {
    const override = /^\s*override=(.+)$/m.exec(out)?.[1]?.trim();
    if (override !== undefined) {
      // e.g. "override=security disabled": the host is not enforcing assessments.
      return { assessment: "unknown", override, exitCode: 0, note: `spctl reported accepted but override=${override}; the host is not enforcing Gatekeeper, so this is not a real verdict` };
    }
    const source = /^\s*source=(.+)$/m.exec(out)?.[1]?.trim();
    const origin = /^\s*origin=(.+)$/m.exec(out)?.[1]?.trim();
    return { assessment: "accepted", source, origin, exitCode: 0 };
  }
  if (verdictLine.includes("rejected")) {
    return { assessment: "rejected", exitCode: r.code, note: out.split("\n")[0]?.trim() };
  }
  return { assessment: "unknown", exitCode: r.code, note: out.length > 0 ? out.split("\n")[0]?.trim() : "no output" };
}

export interface QuarantineResult {
  quarantined: boolean;
  value?: string;
  error?: string;
}

export function quarantineState(path: string, params: ToolParams): QuarantineResult {
  const r = runTool("xattr", ["-p", "com.apple.quarantine", path], params);
  if (r.status !== "ok") {
    return { quarantined: false, error: `xattr could not run (${r.errorCode ?? r.status})` };
  }
  if (r.code === 0) {
    return { quarantined: true, value: r.stdout.trim().split("\n")[0] };
  }
  if (r.stderr.includes("No such xattr")) {
    return { quarantined: false };
  }
  return { quarantined: false, error: r.stderr.trim().split("\n")[0] };
}

export interface StaplerResult {
  validated: boolean;
  exitCode: number;
  note: string;
}

export function staplerValidate(path: string, params: ToolParams): StaplerResult {
  const r = runTool("stapler", ["validate", "-v", path], params);
  if (r.status !== "ok") {
    return { validated: false, exitCode: r.code, note: r.status === "timeout" ? "stapler timed out" : `stapler could not run (${r.errorCode ?? r.status})` };
  }
  const text = (r.stdout + "\n" + r.stderr).trim();
  if (r.code === 0) {
    return { validated: true, exitCode: 0, note: text.split("\n").slice(-1)[0] ?? "" };
  }
  return { validated: false, exitCode: r.code, note: text.split("\n").slice(-1)[0] ?? "no ticket" };
}
