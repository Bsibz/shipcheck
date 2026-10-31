// Shared context + finding factory helpers for all check modules.

import type { Collector, CheckOptions, Finding, Status, TargetMeta } from "./report.js";
import { runTool, type ToolParams } from "./proc.js";
import type { AppStructure } from "./bundle.js";

export interface AuditContext {
  app: AppStructure | undefined;
  target: TargetMeta;
  opts: CheckOptions;
  params: ToolParams;
  collector: Collector;
  toolMissing: Set<string>;
  /** codesign -d of the .app itself (set by runSignatures; reused by later checks). */
  bundleDisplay?: import("./codesign.js").CodeInfo;
  /** True once codesign verified the Developer ID requirement against the bundle. */
  developerIdAnchored?: boolean;
  issues: Array<{ id: string; detail: string; evidence?: string[] }>;
}

export const GROUP = {
  identity: "bundle identity",
  signing: "signing",
  notarization: "notarization",
  gatekeeper: "gatekeeper",
  arch: "architecture",
  asar: "asar",
  native: "native code",
  hashes: "hashes",
  updater: "updater",
  paths: "paths",
  env: "environment",
  entitlements: "entitlements",
} as const;

export function finding(
  id: string,
  group: string,
  status: Status,
  detail: string,
  evidence?: string[],
  hint?: string,
): Finding {
  const f: Finding = { id, group, status, detail };
  if (evidence !== undefined && evidence.length > 0) f.evidence = evidence;
  if (hint !== undefined) f.hint = hint;
  return f;
}

export function fail(id: string, group: string, detail: string, evidence?: string[], hint?: string): Finding {
  return finding(id, group, "fail", detail, evidence, hint);
}

export function warn(id: string, group: string, detail: string, evidence?: string[], hint?: string): Finding {
  return finding(id, group, "warn", detail, evidence, hint);
}

export function pass(id: string, group: string, detail: string, evidence?: string[]): Finding {
  return finding(id, group, "pass", detail, evidence);
}

export function info(id: string, group: string, detail: string, evidence?: string[], hint?: string): Finding {
  return finding(id, group, "info", detail, evidence, hint);
}

export function unknown(id: string, group: string, detail: string, evidence?: string[], hint?: string): Finding {
  return finding(id, group, "unknown", detail, evidence, hint);
}

export function skip(id: string, group: string, detail: string): Finding {
  return finding(id, group, "skip", detail);
}

/** Run a host tool, tracking availability failures once. */
export function run(ctx: AuditContext, tool: string, args: readonly string[], maxOutputKiB = 64) {
  const result = runTool(tool, args, ctx.params, maxOutputKiB);
  if (result.status === "missing") {
    ctx.toolMissing.add(tool);
  }
  return result;
}

export function toolAvailableGuard(ctx: AuditContext, tool: string, checkId: string, group: string): boolean {
  if (!ctx.toolMissing.has(tool)) return true;
  ctx.collector.add(
    unknown(checkId, group, `Required host tool ${tool} is missing; this check cannot run.`, undefined, "Install the full macOS Command Line Tools."),
  );
  return false;
}
