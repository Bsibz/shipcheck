// Shared check/report model.
//
// Status vocabulary is deliberately small and never collapses "unknown" into
// "pass" — evidence honesty beats tidy reports.

export type Status = "pass" | "warn" | "fail" | "info" | "unknown" | "skip";

/**
 * How the finding is grounded:
 *   verified — directly observed from the artifact or an Apple tool's output
 *   inferred — a heuristic / indirect conclusion (byte scans, absence-of-line
 *              reasoning, assessments of an extracted copy rather than the download)
 *   unknown  — could not be determined; never to be read as a pass
 */
export type Basis = "verified" | "inferred" | "unknown";

export interface Finding {
  id: string;
  group: string;
  status: Status;
  /** Evidence grounding; assigned by the Collector when a check does not set it. */
  basis?: Basis;
  /** One-line human summary. */
  detail: string;
  /** Optional hard evidence lines (raw tool lines, hashes, paths). */
  evidence?: string[];
  /** Optional remediation hint. */
  hint?: string;
}

export interface TargetMeta {
  kind: "bundle" | "zip" | "dmg";
  /** The path as the user gave it. */
  input: string;
  /** The .app bundle actually audited (inside a temp tree for zips). */
  bundlePath?: string;
  bundleName?: string;
  /** Other .app bundles found in a zip (by name). */
  otherBundles?: string[];
  /** Archive statistics for zip inputs (declared, pre-extraction). */
  zip?: {
    archiveBytes: number;
    entries: number;
    uncompressedBytes: number;
    skippedMetadataEntries: number;
    extractedFiles?: number;
    extractedSymlinks?: number;
  };
}

export interface Provenance {
  artifact: {
    path: string;
    realPath?: string;
    kind: "bundle" | "zip" | "dmg";
    sizeBytes?: number;
    modified?: string;
    /** SHA-256 of the artifact file (zip inputs). Directories are not hashed as a whole. */
    sha256?: string;
    sha256Basis: "file-stream" | "not-applicable-directory" | "unavailable" | "changed-during-audit";
    /** The .app directory actually audited (real path); differs from `path` for ZIP inputs or when a path inside the bundle was given. */
    auditedBundle?: string;
  };
  /**
   * "offline": shipcheck has no network client and invoked no tool known to
   * contact Apple. "may-contact-apple": an opted-in tool (see networkTools)
   * may. Neither is OS-enforced: tools are not sandboxed.
   */
  network: "offline" | "may-contact-apple";
  /** Opted-in host tools that may contact Apple (empty when offline). */
  networkTools: string[];
  networkNote: string;
  extraction: "none" | "confined-pure-ts-extract-to-private-temp";
  /** Host tools actually invoked → absolute path (never resolved through PATH). */
  hostTools?: Record<string, string>;
  /** How host tools were spawned (fixed absolute paths, scrubbed environment). */
  toolEnvironment?: string;
  limits?: Record<string, number>;
  generatedBy: string;
}

export interface CheckOptions {
  failOn: "fail" | "warn" | "never";
  /** Fail CI when recorded unknown or skipped findings remain. */
  strict?: boolean;
  asarDepth: "none" | "header" | "files";
  hashes: "none" | "key" | "all";
  universal: boolean;
  pathsScan: "main" | "all";
  stapler: boolean;
  /** Run 'spctl' (Gatekeeper assessment). Opt-in: it may contact Apple. */
  gatekeeper: boolean;
  hints: boolean;
  timeoutMs: number;
  /** Explicit local updater sidecars; never fetched or executed. */
  updateMetadata?: string[];
}

export const defaultOptions: CheckOptions = {
  failOn: "fail",
  strict: false,
  asarDepth: "header",
  hashes: "key",
  universal: false,
  pathsScan: "main",
  stapler: false,
  gatekeeper: false,
  hints: true,
  timeoutMs: 90_000,
};

export interface RuntimeInfo {
  macos: string;
  arch: string;
  node: string;
}

export interface Report {
  tool: "shipcheck";
  version: string;
  reportVersion: 1;
  timestamp: string;
  runtime: RuntimeInfo;
  target: TargetMeta;
  provenance: Provenance;
  options: CheckOptions;
  /** Notes about tool behavior the reader should know (temp dirs, network probes used). */
  notes: string[];
  findings: Finding[];
  summary: Record<Status, number>;
  basisSummary: Record<Basis, number>;
  verdict: "clean" | "warnings" | "failures";
}

/** Heuristic checks (byte scans, file-presence reasoning). */
const INFERRED_PREFIXES = ["paths.", "updater.", "native.host-paths", "arch.native-prebuilds"];

const ORDER: Status[] = ["pass", "info", "warn", "fail", "unknown", "skip"];

/** Unknown and skipped findings are unresolved. Callers must not render them as passes. */
export function unresolvedSummary(summary: Record<Status, number>): { unknown: number; skip: number; total: number } {
  const unknown = summary.unknown ?? 0;
  const skip = summary.skip ?? 0;
  return { unknown, skip, total: unknown + skip };
}

export class Collector {
  findings: Finding[] = [];

  /** Set by the CLI so basis rules can account for how the target was obtained. */
  targetKind: TargetMeta["kind"] = "bundle";

  add(f: Finding): void {
    this.findings.push({ ...f, basis: f.basis ?? this.basisFor(f) });
  }

  private basisFor(f: Finding): Basis {
    if (f.status === "unknown" || f.status === "skip") return "unknown";
    if (INFERRED_PREFIXES.some((p) => f.id.startsWith(p))) return "inferred";
    // Absence of a codesign line is not a stapler verdict.
    if (f.id === "not.stapled" && f.status !== "pass") return "inferred";
    // Gatekeeper/quarantine of an extracted copy is not what a downloaded copy would hit.
    if (this.targetKind === "zip" && f.id.startsWith("gatekeeper.")) return "inferred";
    return "verified";
  }

  byId(id: string): Finding | undefined {
    return this.findings.find((f) => f.id === id);
  }

  summary(): Record<Status, number> {
    const s: Record<Status, number> = { pass: 0, warn: 0, fail: 0, info: 0, unknown: 0, skip: 0 };
    for (const f of this.findings) s[f.status] += 1;
    return s;
  }

  basisSummary(): Record<Basis, number> {
    const s: Record<Basis, number> = { verified: 0, inferred: 0, unknown: 0 };
    for (const f of this.findings) s[f.basis ?? "verified"] += 1;
    return s;
  }

  worst(): "clean" | "warnings" | "failures" {
    if (this.findings.some((f) => f.status === "fail")) return "failures";
    if (this.findings.some((f) => f.status === "warn")) return "warnings";
    return "clean";
  }
}

export function finalizeReport(
  target: TargetMeta,
  options: CheckOptions,
  collector: Collector,
  notes: string[],
  version: string,
  runtime: RuntimeInfo,
  provenance: Provenance,
): Report {
  return sanitizeDeep({
    tool: "shipcheck",
    version,
    reportVersion: 1,
    timestamp: new Date().toISOString(),
    runtime,
    target,
    provenance,
    options,
    notes,
    findings: collector.findings,
    summary: collector.summary(),
    basisSummary: collector.basisSummary(),
    verdict: collector.worst(),
  });
}

// Artifact-derived strings (plist values, paths, tool output) are untrusted.
// Neutralize terminal escapes, control characters and bidi overrides so that
// no renderer (text/markdown/html) can be driven by artifact content.
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

export function sanitizeString(s: string): string {
  return s.replace(UNSAFE_CHARS, "\uFFFD");
}

export function sanitizeDeep<T>(v: T): T {
  if (typeof v === "string") return sanitizeString(v) as unknown as T;
  if (Array.isArray(v)) return v.map((x) => sanitizeDeep(x)) as unknown as T;
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = sanitizeDeep(x);
    return out as T;
  }
  return v;
}

export { ORDER };
