// Input traversal: turn ".app path" or "release zip path" into a bundle path
// plus target metadata, with temp extraction for zips. Read-only against the
// artifact: the source zip is never modified; egress is a fresh temp tree
// owned (and disposed) by the caller.

import { basename, join } from "node:path";
import { existsSync, lstatSync, readdirSync } from "node:fs";
import { makeTempTree, type TempTree } from "./temp.js";
import { readAppStructure, nfc, type AppStructure } from "./bundle.js";
import type { ToolParams } from "./proc.js";
import { DEFAULT_ZIP_LIMITS, pinZip, planZip, type PinnedZip, type ZipLimits, type ZipViolation } from "./zipsafe.js";
import { extractPlan } from "./temp.js";

export interface TargetMetaPartial {
  kind: "bundle" | "zip" | "dmg";
  input: string;
  bundlePath?: string;
  bundleName?: string;
  otherBundles?: string[];
  zip?: ZipStats;
}

export interface ZipStats {
  archiveBytes: number;
  entries: number;
  uncompressedBytes: number;
  skippedMetadataEntries: number;
  extractedFiles?: number;
  extractedSymlinks?: number;
}

export type TraversalIssueId =
  | "input-not-found"
  | "input-unrecognized"
  | "zip-extract-failed"
  | "zip-unsafe"
  | "zip-no-app"
  | "zip-multiple-apps";

export interface TraversalIssue {
  id: TraversalIssueId;
  detail: string;
  evidence?: string[];
}

export interface ResolvedTarget {
  target: TargetMetaPartial;
  app?: AppStructure;
  /** Owned by the caller; dispose when the audit completes. */
  tempTree?: TempTree;
  /**
   * ZIP inputs: the descriptor everything was read through, plus its SHA-256.
   * Owned by the caller: check `changed()` after the audit, then `close()`.
   */
  zipPin?: PinnedZip;
  issues: TraversalIssue[];
}

export function isZipPath(input: string): boolean {
  return nfc(basename(input)).toLowerCase().endsWith(".zip");
}

export function resolveTarget(input: string, params: ToolParams, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ResolvedTarget {
  const issues: TraversalIssue[] = [];

  let st;
  try {
    st = lstatSync(input);
  } catch {
    issues.push({ id: "input-not-found", detail: "Input path does not exist (or is not readable)." });
    return { target: { kind: "bundle", input }, issues };
  }
  if (/\.dmg$/i.test(basename(input))) {
    if (!st.isFile()) issues.push({ id: "input-unrecognized", detail: "DMG input must be a local regular file; symlinks and devices are refused." });
    return { target: { kind: "dmg", input }, issues };
  }

  if (isZipPath(input)) {
    return resolveZip(input, issues, params, limits);
  }

  const bundle = resolveAppBundleDir(input);
  if (bundle === undefined) {
    issues.push({
      id: "input-unrecognized",
      detail: "Not a .app bundle, a ZIP, a DMG, or the Contents of an app — nothing auditable.",
    });
    return { target: { kind: "bundle", input }, issues };
  }
  const app = readAppStructure(bundle);
  return {
    target: { kind: "bundle", input, bundlePath: bundle, bundleName: basename(bundle) },
    app,
    issues,
  };
}

function resolveZip(input: string, issues: TraversalIssue[], params: ToolParams, limits: ZipLimits): ResolvedTarget {
  void params;
  // 1. Plan: parse + validate the central directory without writing anything.
  // The ZIP is opened exactly once. Hash, plan and extraction all read this fd.
  let pin: PinnedZip;
  try {
    pin = pinZip(input);
  } catch (e) {
    issues.push({ id: "zip-extract-failed", detail: `Release ZIP could not be read: ${e instanceof Error ? e.message : String(e)}` });
    return { target: { kind: "zip", input }, issues };
  }
  const resolved = resolveZipPinned(input, pin, issues, limits);
  resolved.zipPin = pin;
  return resolved;
}

function resolveZipPinned(input: string, pin: PinnedZip, issues: TraversalIssue[], limits: ZipLimits): ResolvedTarget {
  let plan;
  try {
    plan = planZip(pin.fd, limits);
  } catch (e) {
    issues.push({ id: "zip-extract-failed", detail: `Release ZIP could not be read: ${e instanceof Error ? e.message : String(e)}` });
    return { target: { kind: "zip", input }, issues };
  }
  const zipStats: ZipStats = {
    archiveBytes: plan.archiveBytes,
    entries: plan.entryCount,
    uncompressedBytes: plan.totalUncompressed,
    skippedMetadataEntries: plan.skippedMetadata,
  };
  if (plan.violations.length > 0) {
    issues.push({
      id: "zip-unsafe",
      detail: `Release ZIP rejected before extraction: ${summarizeViolations(plan.violations)}. Nothing was extracted or audited.`,
      evidence: plan.violations.slice(0, 20).map((v) => `${v.id}: ${v.detail}${v.entry !== undefined ? ` [${v.entry}]` : ""}`),
    });
    return { target: { kind: "zip", input, zip: zipStats }, issues };
  }

  // 2. Confined extraction into a fresh private temp tree.
  const tempTree = makeTempTree("shipcheck-zip-");
  try {
    let res;
    try {
      res = extractPlan(pin.fd, plan, tempTree.root, limits.maxTotalBytes, limits.maxEntryBytes);
    } catch (e) {
      issues.push({
        id: "zip-extract-failed",
        detail: `Release ZIP could not be extracted safely: ${e instanceof Error ? e.message : String(e)}`,
      });
      tempTree.dispose();
      return { target: { kind: "zip", input, zip: zipStats }, issues };
    }
    zipStats.extractedFiles = res.files;
    zipStats.extractedSymlinks = res.symlinks;
    const bundle = findAppBundle(tempTree.root);
    if (bundle === undefined) {
      issues.push({
        id: "zip-no-app",
        detail: "No .app bundle inside the ZIP. shipcheck audits macOS .app payloads; other platforms are out of scope.",
      });
      return { target: { kind: "zip", input, zip: zipStats }, issues, tempTree };
    }
    const others = listOtherBundles(tempTree.root, bundle);
    if (others.length > 0) {
      issues.push({
        id: "zip-multiple-apps",
        detail: `Multiple .app bundles found; auditing "${basename(bundle)}" only.`,
        evidence: others.map((p) => basename(p)),
      });
    }
    const app = readAppStructure(bundle);
    return {
      target: {
        kind: "zip",
        input,
        bundlePath: bundle,
        bundleName: basename(bundle),
        otherBundles: others.length > 0 ? others : undefined,
        zip: zipStats,
      },
      app,
      tempTree,
      issues,
    };
  } catch (e) {
    tempTree.dispose();
    issues.push({ id: "zip-extract-failed", detail: `Release ZIP handling failed: ${e instanceof Error ? e.message : String(e)}` });
    return { target: { kind: "zip", input, zip: zipStats }, issues };
  }
}

function summarizeViolations(vs: ZipViolation[]): string {
  const counts = new Map<string, number>();
  for (const v of vs) counts.set(v.id, (counts.get(v.id) ?? 0) + 1);
  return [...counts.entries()].map(([id, n]) => `${id}×${n}`).join(", ");
}

export function resolveAppBundleDir(input: string): string | undefined {
  let cur = input;
  for (let i = 0; i < 5; i += 1) {
    if (isAppDir(cur)) return cur;
    const parent = join(cur, "..");
    if (parent === cur) break;
    cur = parent;
  }
  return undefined;
}

function isAppDir(p: string): boolean {
  try {
    if (!lstatSync(p).isDirectory()) return false;
    if (!nfc(basename(p)).toLowerCase().endsWith(".app")) return false;
    return existsSync(join(p, "Contents", "Info.plist"));
  } catch {
    return false;
  }
}

export function findAppBundle(rootDir: string): string | undefined {
  const hits = listAppBundles(rootDir);
  if (hits.length === 0) return undefined;
  hits.sort((a, b) => a.split("/").length - b.split("/").length || a.localeCompare(b));
  return hits[0];
}

export function listOtherBundles(rootDir: string, chosen: string): string[] {
  return listAppBundles(rootDir)
    .filter((p) => p !== chosen)
    .sort();
}

function listAppBundles(rootDir: string, maxDepth = 8): string[] {
  const out: string[] = [];
  const visit = (dir: string, depth: number): void => {
    if (depth > maxDepth || out.length >= 50) return;
    let names: string[];
    try {
      names = readdirSync(dir, { withFileTypes: true }).map((d) => d.name);
    } catch {
      return;
    }
    for (const name of names) {
      const p = join(dir, name);
      let s;
      try {
        s = lstatSync(p);
      } catch {
        continue;
      }
      if (s.isSymbolicLink()) continue;
      if (s.isDirectory()) {
        if (nfc(name).toLowerCase().endsWith(".app") && existsSync(join(p, "Contents", "Info.plist"))) {
          out.push(p);
          continue; // helpers live inside apps; do not descend
        }
        visit(p, depth + 1);
      }
    }
  };
  visit(rootDir, 0);
  return out;
}
