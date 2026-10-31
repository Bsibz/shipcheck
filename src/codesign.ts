// codesign-based signing facts.
//
// Parsing is shaped by captured outputs on this macOS release family (see
// test/fixtures/data). Verified truths:
//   - `codesign -d --verbose=4` prints key=value lines; failures print on
//     stderr ("code object is not signed at all").
//   - Hardened runtime appears as `flags=0x...(...,runtime,...)`, bit 0x10000.
//   - Ad-hoc shows `Signature=adhoc` and/or an `adhoc` flag name.
//   - A Mach-O the linker signed on its own shows flags=(adhoc,linker-signed)
//     with `Sealed Resources=none` and `Info.plist=not bound`; an ad-hoc-signed
//     .app shows flags=(adhoc) with `Sealed Resources version=…` and a
//     Contents/_CodeSignature directory. The adhoc flag alone does not mean
//     the bundle is ad-hoc signed.
//   - `--entitlements :-` prints an XML plist on stdout (empty stdout when the
//     target carries no entitlements) with a harmless deprecation warning on
//     stderr.

import { asDict, parsePlistXml } from "./plist.js";
import { runTool, type ToolParams, type ToolResult } from "./proc.js";

export const HARDENED_RUNTIME_BIT = 0x10000;

const KNOWN_ARCHS = new Set(["x86_64", "i386", "arm64", "arm64e", "armv7", "armv7k", "ppc", "ppc64", "x86_64h"]);

export interface EntitlementsInfo {
  present: boolean;
  dict?: Record<string, unknown>;
  error?: string;
}

export interface CodeInfo {
  notSigned: boolean;
  identifier?: string;
  archs?: string[];
  /** Parsed flag names, e.g. ["adhoc","runtime"] or ["none"]. */
  flagNames: string[];
  hardenedRuntime: boolean;
  authority: string[];
  teamIdentifier?: string;
  /** The adhoc flag is present. Scope (bundle vs bare Mach-O) is decided by classifyAdhoc. */
  signatureAdhoc: boolean;
  /** The linker-signed flag: the linker produced this CodeDirectory, nothing signed the bundle. */
  linkerSigned: boolean;
  /** codesign's `Sealed Resources` fact. Undefined when the line is absent (unknown). */
  sealedResources?: boolean;
  cdHash?: string;
  timestamp?: string;
  /** codesign's own stapling fact (Notarization Ticket=stapled / absent). */
  notarizationStapled: boolean;
  entitlements: EntitlementsInfo;
  /** Set when codesign gave no verdict (timeout, missing, output overflow, crash). Distinct from "not signed". */
  toolUnavailable?: string;
}

function parseFlagNames(codeDirectoryLine: string | undefined): string[] {
  const m = codeDirectoryLine?.match(/flags=0x[0-9a-fA-F]+\(([^)]*)\)/);
  if (!m) return ["unknown"];
  const names = (m[1] ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  return names.length > 0 ? names : ["none"];
}

export function parseFlagBitsAndNames(codeDirectoryLine: string | undefined): { bitMask: number; names: string[] } {
  let bitMask = 0;
  const hex = codeDirectoryLine?.match(/flags=0x([0-9a-fA-F]+)/);
  if (hex) bitMask = parseInt(hex[1] ?? "0", 16);
  return { bitMask, names: parseFlagNames(codeDirectoryLine) };
}

export function parseFormatArchs(formatLine: string | undefined): string[] | undefined {
  if (!formatLine) return undefined;
  const m = formatLine.match(/\(([^)]+)\)/);
  if (!m) return undefined;
  const inside = (m[1] ?? "").trim();
  if (!/mach-o/i.test(formatLine)) return undefined;
  const archs = inside
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
    .filter((t) => t.startsWith("universal") || KNOWN_ARCHS.has(t) || /^\w+/.test(t));
  return archs.length > 0 ? archs : undefined;
}

export function parseDisplay(stdout: string, stderr: string, exitCode: number): CodeInfo {
  const notSigned = stderr.includes("not signed at all") || stdout.includes("not signed at all");
  const base: CodeInfo = {
    notSigned,
    flagNames: [],
    hardenedRuntime: false,
    authority: [],
    signatureAdhoc: false,
    linkerSigned: false,
    notarizationStapled: false,
    entitlements: { present: false },
  };
  if ((notSigned || exitCode !== 0) && !stdout.includes("Identifier=")) {
    return base;
  }
  const kv = new Map<string, string>();
  const authority: string[] = [];
  let codeDirectoryLine: string | undefined;
  for (const rawLine of (stdout + "\n" + stderr).split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("CodeDirectory")) {
      codeDirectoryLine = line.slice("CodeDirectory".length).trim();
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1);
    if (key === "Authority") authority.push(value);
    else if (key.length <= 40) kv.set(key, value);
  }
  const cdLine = codeDirectoryLine !== undefined ? `CodeDirectory ${codeDirectoryLine}` : kv.get("CodeDirectory");
  const { bitMask, names } = parseFlagBitsAndNames(cdLine);
  const adhoc = kv.get("Signature") === "adhoc" || names.includes("adhoc");
  const notarRaw = kv.get("Notarization Ticket") ?? kv.get("Notarization") ?? "";

  // Team comes only from codesign's TeamIdentifier line. The "(TEAMID)" suffix
  // of a certificate display name is chosen by whoever made the certificate,
  // so it is never used as a fallback.
  const team = kv.get("TeamIdentifier");
  // codesign prints either `Sealed Resources=none` or
  // `Sealed Resources version=2 rules=13 files=0`.
  const sealedRaw = kv.get("Sealed Resources");
  const sealedResources =
    sealedRaw !== undefined ? !/^none\s*$/i.test(sealedRaw.trim()) : kv.has("Sealed Resources version") ? true : undefined;

  return {
    notSigned,
    identifier: kv.get("Identifier"),
    archs: parseFormatArchs(kv.get("Format")),
    flagNames: names,
    hardenedRuntime: names.includes("runtime") || (bitMask & HARDENED_RUNTIME_BIT) !== 0,
    authority,
    teamIdentifier: team,
    signatureAdhoc: adhoc,
    linkerSigned: names.includes("linker-signed"),
    sealedResources,
    cdHash: kv.get("CDHash"),
    timestamp: kv.get("Timestamp") ?? kv.get("Sign time"),
    notarizationStapled: notarRaw.toLowerCase().includes("stapled"),
    entitlements: { present: false },
  };
}

export function displayInfo(path: string, params: ToolParams): CodeInfo {
  const r = runTool("codesign", ["-d", "--verbose=4", path], params);
  if (r.status !== "ok") {
    const base = parseDisplay("", "", -1);
    return { ...base, toolUnavailable: toolFailure("codesign -d", r) };
  }
  // codesign -d prints its facts on STDERR; stdout stays empty.
  return parseDisplay(r.stdout + "\n" + r.stderr, "", r.code);
}

export type AdhocKind = "none" | "bundle-adhoc" | "linker-only" | "unknown";

/**
 * Scope of an ad-hoc signature. `flags=(adhoc)` on its own is ambiguous: every
 * arm64 Mach-O the linker emits carries one, and `codesign -d` on an unsigned
 * .app reports that inner signature. Only a bundle-level signature — a
 * Contents/_CodeSignature directory plus sealed resources, with no
 * linker-signed flag — means the .app itself was signed ad-hoc.
 */
export function classifyAdhoc(display: CodeInfo, bundleHasCodeSignature: boolean): AdhocKind {
  if (display.notSigned || !display.signatureAdhoc) return "none";
  if (display.linkerSigned) return "linker-only";
  if (!bundleHasCodeSignature) return "linker-only";
  if (display.sealedResources === true) return "bundle-adhoc";
  if (display.sealedResources === false) return "linker-only";
  return "unknown";
}

export function parseEntitlementsOutput(stdout: string): EntitlementsInfo {
  let text = stdout;
  if (text.startsWith("Executable=")) {
    const idx = text.indexOf("<?xml");
    if (idx > 0) text = text.slice(idx);
  }
  if (!text.includes("<plist")) {
    return { present: false };
  }
  const parsed = parsePlistXml(text);
  const dict = asDict(parsed.value) as Record<string, unknown> | undefined;
  if (parsed.ok && dict !== undefined) {
    return { present: true, dict };
  }
  return { present: false, error: "entitlements plist unparseable" };
}

export function toolFailure(what: string, r: ToolResult): string {
  return r.status === "timeout"
    ? `${what} timed out`
    : r.status === "missing"
      ? `${what} could not be started (${r.errorCode ?? "missing"})`
      : `${what} produced no usable result (${r.errorCode ?? "error"})`;
}

export function displayEntitlements(path: string, params: ToolParams): EntitlementsInfo {
  const r = runTool("codesign", ["-d", "--entitlements", ":-", path], params);
  if (r.status !== "ok") return { present: false, error: toolFailure("codesign --entitlements", r) };
  return parseEntitlementsOutput(r.stdout);
}

export interface VerifyResult {
  ok: boolean;
  exitCode: number;
  detail: string[];
  notSigned: boolean;
  archNote?: string;
  /** Set when codesign gave no verdict (timeout, missing, overflow, crash): result is unknown, not "broken". */
  toolUnavailable?: string;
}

export function verifyStrict(path: string, deep: boolean, params: ToolParams): VerifyResult {
  const args: string[] = ["--verify", "--strict", "--verbose=2"];
  if (deep) args.push("--deep");
  args.push(path);
  const r = runTool("codesign", args, params, 256 * 1024);
  if (r.status !== "ok") {
    return { ok: false, exitCode: r.code, detail: [], notSigned: false, toolUnavailable: toolFailure("codesign --verify", r) };
  }
  const text = r.stdout + "\n" + r.stderr;
  const detail = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("--"));
  const notSigned = text.includes("not signed at all");
  const archNote = /In architecture: (\S+)/.exec(text)?.[1];
  return { ok: r.code === 0, exitCode: r.code, detail, notSigned, archNote };
}

/**
 * Apple's own definition of "Developer ID Application, issued by Apple's
 * Developer ID CA": anchored to Apple's root, with the Developer ID CA
 * intermediate extension (…6.2.6) and the Developer ID Application leaf
 * extension (…6.1.13). Evaluated by codesign itself, not parsed from names.
 */
export const DEVELOPER_ID_REQUIREMENT =
  "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";

export interface RequirementResult {
  satisfied: boolean;
  toolUnavailable?: string;
  detail: string[];
}

export function verifyDeveloperIdRequirement(path: string, params: ToolParams): RequirementResult {
  // No --strict: this asks only "does the certificate chain satisfy the Developer ID
  // requirement". Strict resource hygiene (e.g. Finder detritus) is sign.validity's job.
  const r = runTool("codesign", ["--verify", `-R=${DEVELOPER_ID_REQUIREMENT}`, path], params, 256 * 1024);
  if (r.status !== "ok") return { satisfied: false, toolUnavailable: toolFailure("codesign -R", r), detail: [] };
  const detail = (r.stdout + "\n" + r.stderr).split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  if (r.code !== 0 && !/failed to satisfy/i.test(detail.join("\n"))) {
    // Failed for some other reason (unreadable bundle, bad signature): no trust verdict either way.
    return { satisfied: false, toolUnavailable: `codesign -R exited ${r.code} without a requirement verdict`, detail };
  }
  return { satisfied: r.code === 0, detail };
}

export type SignerClass = "developer-id" | "apple-development" | "app-store" | "self-signed-or-other" | "none";

/** Name-based hint only. Display names are chosen by the certificate's creator; this is never proof. */
export function classifyAuthority(authority: readonly string[]): SignerClass {
  const leaf = authority[0];
  if (leaf === undefined) return "none";
  if (leaf.startsWith("Developer ID Application:")) return "developer-id";
  if (/^(Apple Development|Mac Developer|iPhone Developer):/.test(leaf)) return "apple-development";
  if (leaf.startsWith("Apple Distribution:") || leaf.startsWith("3rd Party Mac Developer Application:") || leaf.startsWith("Mac App Distribution:")) return "app-store";
  return "self-signed-or-other";
}
