#!/usr/bin/env node
// shipcheck CLI entry: argument parsing, orchestration, exit codes.
//
// Exit codes (CI contract, documented in README):
//   0 clean — no findings above info
//   1 warnings (default --fail-on fail)
//   2 failures (or warnings under --fail-on warn)
//   3 usage/argument error
//   4 environment error (not macOS, or required host tools missing)
//   5 report could not be written (--out path unusable)
//   6 unresolved findings under --strict
//
// Read-only contract: shipcheck never modifies the inspected artifact, never
// signs, notarizes, uploads or deletes anything except its own temp
// extraction tree.

import { realpathSync, statSync } from "node:fs";
import os from "node:os";
import process from "node:process";
import { defaultOptions, finalizeReport, type CheckOptions, type Provenance, type Report, type RuntimeInfo, type Status, type TargetMeta } from "./report.js";
import { resolveTarget, type TraversalIssue } from "./input.js";
import type { AuditContext } from "./checkscommon.js";
import { Collector } from "./report.js";
import { runIdentity, runSignatures } from "./checks-identity.js";
import { runNotarization, runGatekeeperChecks } from "./checks-notary.js";
import { runEntitlements } from "./checks-ent.js";
import { runArchitecture } from "./checks-arch.js";
import { runAsarChecks } from "./checks-asarx.js";
import { runNativeChecks, MAX_MACHO_ANALYZED } from "./checks-native.js";
import { MAX_UPDATE_METADATA_BYTES } from "./update-metadata.js";
import { runDmgChecks } from "./checks-dmg.js";
import { runUpdaterChecks } from "./checks-updater.js";
import { runPathScanChecks } from "./checks-paths.js";
import { runHashChecks } from "./checks-hashes.js";
import { renderText } from "./render/text.js";
import { renderMarkdown } from "./render/markdown.js";
import { missingTools, toolEnvironmentNote, usedToolPaths } from "./proc.js";
import { validateOutputs, writeReport, type OutputTarget } from "./output.js";
import { DEFAULT_ZIP_LIMITS, type PinnedZip, type ZipLimits } from "./zipsafe.js";
import packageJson from "../package.json";

const VERSION: string = (packageJson as { version: string }).version;
const USAGE = `shipcheck ${VERSION} — read-only ship-check for macOS/Electron artifacts

USAGE
  shipcheck <path.app | release.zip | release.dmg> [options]

Audit a .app bundle (path may point at the bundle, its Contents/, or an
executable inside it) or a release ZIP (validated, then extracted by a
bounded in-process reader to a private temp dir; macOS .app payloads only).
DMG inputs get non-mounting container metadata only; payload checks stay UNKNOWN.
Offline by default: no network client exists in shipcheck and no tool known to
contact Apple runs unless you opt in (--gatekeeper, --stapler). This is by
design, not OS-enforced. Nothing from the artifact is ever executed.

OPTIONS
  --format text|json|markdown|html
                                stdout format (default: text)
  --out FILE                    additionally write the --format report to FILE
  --json FILE                   also write the JSON receipt to FILE
  --html FILE                   also write the HTML report to FILE
                                (FILE may never be the audited artifact, inside
                                it (case-insensitively), a hard link, or another
                                output; checked before the audit. An existing FILE
                                is refused unless --force)
  --force                       allow --out/--json/--html to replace an existing
                                regular file (never the artifact or a hard link)
  --update-metadata FILE        inspect local latest-mac YAML or appcast XML
                                fields (repeat up to 8 times; never fetch feeds)
  --max-zip-gib N               cap on total uncompressed ZIP bytes
                                (default: 8; per-entry cap 2 GiB, 200k entries,
                                1000:1 ratio above 16 MiB)
  --fail-on fail|warn|never     exit-code policy (default: fail)
  --strict                      exit 6 for UNKNOWN/skipped findings; incompatible
                                with --fail-on never (default: off)
  --asar-depth none|header|files
                                none/header fast; files verifies per-entry
                                integrity records (default: header)
  --hashes none|key|all         SHA-256 coverage: key executables, or
                                everything incl. asar+native (default: key)
  --universal                   require a universal (multi-arch) main binary
  --paths-scan main|all         byte-scan main exe only or all framework
                                binaries too (default: main)
  --gatekeeper                  ALSO run 'spctl' (Gatekeeper assessment) — note: it
                                may contact Apple (opt-in only); without it the
                                Gatekeeper verdict is reported as UNKNOWN
  --stapler                     ALSO run 'stapler validate' — note: it may
                                download the ticket from Apple (opt-in only)
  --no-hints                    drop remediation hints
  --timeout-sec N               per host-tool call timeout (default: 90)
  --version, --help

EXIT CODES
  0 clean   1 warnings   2 failures   3 bad usage   4 bad environment
  5 could not write an output file (--out/--json/--html)
  6 unresolved UNKNOWN/skipped findings under --strict

Exit 0 means no warning or failure under the selected policy. Unknown and
skipped checks can still be present unless --strict is selected. Text then prints
an UNRESOLVED line after VERDICT. Unknown is not a pass, and exit 0 is not a ship certificate.

Read-only. Never signs, notarizes, uploads or mutates the audited artifact.`;

interface ParsedArgs {
  input?: string;
  opts: CheckOptions;
  format: "text" | "json" | "markdown" | "html";
  out?: string;
  json?: string;
  html?: string;
  force: boolean;
  zipLimits: ZipLimits;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: string[]): ParsedArgs | number {
  const args = [...argv];
  const parsed: ParsedArgs = { opts: { ...defaultOptions }, format: "text", force: false, zipLimits: { ...DEFAULT_ZIP_LIMITS }, help: false, version: false };
  while (args.length > 0) {
    const a = args.shift() as string;
    const take = (): string => {
      if (args.length === 0) throw new Error(`missing value for ${a}`);
      return args.shift() as string;
    };
    switch (a) {
      case "--help":
      case "-h":
        parsed.help = true;
        break;
      case "--version":
        parsed.version = true;
        break;
      case "--format": {
        const v = take();
        if (v !== "text" && v !== "json" && v !== "markdown" && v !== "html") throw new Error(`--format must be text|json|markdown|html, got ${v}`);
        parsed.format = v;
        break;
      }
      case "--out":
        parsed.out = take();
        break;
      case "--json":
        parsed.json = take();
        break;
      case "--html":
        parsed.html = take();
        break;
      case "--force":
        parsed.force = true;
        break;
      case "--update-metadata":
        (parsed.opts.updateMetadata ??= []).push(take());
        if (parsed.opts.updateMetadata.length > 8) throw new Error("--update-metadata accepts at most eight files");
        break;
      case "--max-zip-gib": {
        const n = Number(take());
        if (!Number.isFinite(n) || n <= 0 || n > 64) throw new Error("--max-zip-gib expects a number in (0, 64]");
        parsed.zipLimits.maxTotalBytes = Math.floor(n * 1024 ** 3);
        break;
      }
      case "--strict":
        parsed.opts.strict = true;
        break;
      case "--fail-on": {
        const v = take();
        if (v !== "fail" && v !== "warn" && v !== "never") throw new Error(`--fail-on must be fail|warn|never, got ${v}`);
        parsed.opts.failOn = v;
        break;
      }
      case "--asar-depth": {
        const v = take();
        if (v !== "none" && v !== "header" && v !== "files") throw new Error(`--asar-depth must be none|header|files, got ${v}`);
        parsed.opts.asarDepth = v;
        break;
      }
      case "--hashes": {
        const v = take();
        if (v !== "none" && v !== "key" && v !== "all") throw new Error(`--hashes must be none|key|all, got ${v}`);
        parsed.opts.hashes = v;
        break;
      }
      case "--universal":
        parsed.opts.universal = true;
        break;
      case "--paths-scan": {
        const v = take();
        if (v !== "main" && v !== "all") throw new Error(`--paths-scan must be main|all, got ${v}`);
        parsed.opts.pathsScan = v;
        break;
      }
      case "--gatekeeper":
        parsed.opts.gatekeeper = true;
        break;
      case "--stapler":
        parsed.opts.stapler = true;
        break;
      case "--no-hints":
        parsed.opts.hints = false;
        break;
      case "--timeout-sec": {
        const n = Number(take());
        if (!Number.isFinite(n) || n <= 0 || n > 3600) throw new Error(`--timeout-sec expects a number 1..3600`);
        parsed.opts.timeoutMs = n * 1000;
        break;
      }
      default:
        if (a.startsWith("-")) throw new Error(`unknown flag: ${a}`);
        if (parsed.input !== undefined) throw new Error("exactly one audit target is expected");
        parsed.input = a;
        break;
    }
  }
  if (parsed.input === undefined && !parsed.help && !parsed.version) throw new Error("no audit target given");
  if (parsed.opts.strict && parsed.opts.failOn === "never") throw new Error("--strict cannot be combined with --fail-on never");
  return parsed;
}

export function clampToExitCode(verdict: "clean" | "warnings" | "failures", failOn: CheckOptions["failOn"], opts: CheckOptions, summary?: Record<Status, number>): number {
  if (opts.strict && failOn === "never") return 3;
  if (failOn === "never") return 0;
  if (verdict === "failures") return 2;
  if (verdict === "warnings") return failOn === "warn" ? 2 : 1;
  if (opts.strict && (!summary || summary.unknown > 0 || summary.skip > 0)) return 6;
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  let parsed: ParsedArgs | number;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`shipcheck: ${e instanceof Error ? e.message : String(e)}\n\n${USAGE}\n`);
    return 3;
  }
  if (typeof parsed === "number") return parsed;
  if (parsed.help) {
    process.stdout.write(USAGE + "\n");
    return 0;
  }
  if (parsed.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  if (process.platform !== "darwin") {
    process.stderr.write("shipcheck: requires macOS (codesign/spctl/lipo/otool are unavailable here).\n");
    return 4;
  }

  const containerOnly = /\.dmg$/i.test(parsed.input as string);
  const required = containerOnly ? [] : ["codesign", "xattr", "lipo", "otool", "file", "plutil"];
  if (!containerOnly && parsed.opts.gatekeeper) required.push("spctl");
  if (!containerOnly && parsed.opts.stapler) required.push("stapler");
  const absent = missingTools(required);
  if (absent.length > 0) {
    process.stderr.write(`shipcheck: required macOS host tools are missing: ${absent.join(", ")}. Install the Xcode Command Line Tools (xcode-select --install).\n`);
    return 4;
  }

  const runtime: RuntimeInfo = {
    macos: `${os.type()} ${os.release()} (${os.cpus()[0]?.model ?? "unknown-CPU"})`,
    arch: os.arch(),
    node: process.version,
  };

  const collector = new Collector();
  const notes: string[] = [];
  const toolMissing = new Set<string>();
  const params = { timeoutMs: parsed.opts.timeoutMs };

  const outputs: OutputTarget[] = [];
  if (parsed.out !== undefined) outputs.push({ flag: "--out", path: parsed.out });
  if (parsed.json !== undefined) outputs.push({ flag: "--json", path: parsed.json });
  if (parsed.html !== undefined) outputs.push({ flag: "--html", path: parsed.html });
  const outputProblem = validateOutputs(parsed.input as string, outputs, parsed.force);
  if (outputProblem !== undefined) {
    process.stderr.write(`shipcheck: refusing output: ${outputProblem}\n`);
    return 5;
  }
  for (const metadata of parsed.opts.updateMetadata ?? []) {
    const problem = validateOutputs(metadata, outputs, parsed.force);
    if (problem) {
      process.stderr.write(`shipcheck: refusing output over updater metadata: ${problem}\n`);
      return 5;
    }
  }
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.once(sig, () => process.exit(130)); // 'exit' handler disposes the temp tree
  }

  const resolved = resolveTarget(parsed.input as string, params, parsed.zipLimits);
  const zipPin = resolved.zipPin;
  const target: TargetMeta = { ...resolved.target };
  collector.targetKind = target.kind;
  const issues: TraversalIssue[] = resolved.issues;

  if (issues.some((i) => i.id === "input-not-found" || i.id === "input-unrecognized")) {
    for (const issue of issues) {
      process.stderr.write(`shipcheck: ${issue.detail}\n`);
    }
    zipPin?.close();
    return 3;
  }

  const ctx: AuditContext = {
    app: resolved.app,
    target,
    opts: parsed.opts,
    params,
    collector,
    toolMissing,
    issues,
  };
  for (const issue of issues) {
    const status: Status = issue.id === "zip-multiple-apps" ? "warn" : "fail";
    collector.add({ id: `target.${issue.id}`, group: "environment", status, detail: issue.detail, evidence: issue.evidence });
  }
  if (resolved.tempTree !== undefined) {
    notes.push("zip validated and extracted by shipcheck's bounded reader to a private temp dir (removed at exit); no artifact code was executed.");
    if ((target.zip?.skippedMetadataEntries ?? 0) > 0) {
      notes.push(`${target.zip?.skippedMetadataEntries} AppleDouble/__MACOSX metadata entries were not extracted; extended attributes in the zip are not reproduced.`);
    }
  }
  const networkTools = optedInNetworkTools(parsed.opts, containerOnly);
  notes.push(
    networkTools.length > 0
      ? `network: ${networkTools.map((t) => `--${t === "spctl" ? "gatekeeper" : t}`).join(" and ")} requested; ${networkTools.join(" and ")} may contact Apple. shipcheck itself has no network client.`
      : "network: shipcheck has no network client; spctl and stapler were not run. Other host tools (codesign, xattr, lipo, otool, file) were invoked locally and are not sandboxed, so offline operation is by design, not OS-enforced.",
  );
  if (!parsed.opts.gatekeeper) {
    notes.push("gatekeeper: spctl was not run (opt-in via --gatekeeper); the Gatekeeper verdict is UNKNOWN.");
  }

  try {
    runDmgChecks(ctx);
    if (target.kind !== "dmg") runIdentity(ctx);
    runSignatures(ctx);
    runEntitlements(ctx);
    runNotarization(ctx);
    runGatekeeperChecks(ctx);
    runArchitecture(ctx);
    runAsarChecks(ctx);
    runNativeChecks(ctx);
    runUpdaterChecks(ctx);
    runPathScanChecks(ctx);
    await runHashChecks(ctx);
  } finally {
    resolved.tempTree?.dispose();
  }

  // The ZIP's SHA-256 came from the descriptor everything was read through;
  // it is only claimed if neither that fd nor the path drifted since open.
  const artifactChanged = zipPin?.changed() ?? false;
  zipPin?.close();
  const provenance = buildProvenance(parsed, target, zipPin, artifactChanged, resolved.app?.bundleReal);
  if (target.kind === "dmg") notes.push("DMG inspection is container metadata only: no mount, extraction, checksum verification, app discovery or app execution. Payload checks remain UNKNOWN.");
  if (artifactChanged) {
    collector.add({
      id: "provenance.artifact-changed",
      group: "environment",
      status: "fail",
      detail: "The release ZIP changed (device, inode, size or mtime) while it was being audited, so the findings may describe different bytes than the file now on disk; no SHA-256 is claimed for it.",
      hint: "Re-run against an immutable copy of the artifact.",
      basis: "verified",
    });
  }
  const report = finalizeReport(target, parsed.opts, collector, notes, VERSION, runtime, provenance);

  const renderAs = async (fmt: "text" | "json" | "markdown" | "html"): Promise<string> => {
    if (fmt === "json") return JSON.stringify(report, null, 2) + "\n";
    if (fmt === "markdown") return renderMarkdown(report);
    if (fmt === "html") return (await loadHtmlRenderer())(report);
    return renderText(report, parsed.opts.hints);
  };

  let rendered: string;
  try {
    rendered = await renderAs(parsed.format);
  } catch (e) {
    process.stderr.write(`shipcheck: ${e instanceof Error ? e.message : String(e)}\n`);
    return 3;
  }

  let writeFailed = false;
  const emit = async (flag: string, path: string | undefined, fmt: "text" | "json" | "markdown" | "html", cached?: string): Promise<void> => {
    if (path === undefined) return;
    try {
      writeReport(path, cached ?? (await renderAs(fmt)), parsed.force);
      if (flag === "--out") process.stdout.write(`([report written to ${path}])\n`);
      else process.stderr.write(`shipcheck: ${flag} receipt written to ${path}\n`);
    } catch (e) {
      writeFailed = true;
      process.stderr.write(`shipcheck: could not write ${flag}: ${e instanceof Error ? e.message : String(e)}\n`);
    }
  };
  // Receipts first so a stdout consumer never sees them interleaved with the report body.
  await emit("--out", parsed.out, parsed.format, rendered);
  await emit("--json", parsed.json, "json");
  await emit("--html", parsed.html, "html");
  process.stdout.write(rendered);
  if (writeFailed) return 5;

  return clampToExitCode(report.verdict, parsed.opts.failOn, parsed.opts, report.summary);
}

function optedInNetworkTools(opts: CheckOptions, containerOnly = false): string[] {
  if (containerOnly) return [];
  const tools: string[] = [];
  if (opts.gatekeeper) tools.push("spctl");
  if (opts.stapler) tools.push("stapler");
  return tools;
}

function buildProvenance(
  parsed: ParsedArgs,
  target: TargetMeta,
  pin: PinnedZip | undefined,
  changed: boolean,
  bundleReal: string | undefined,
): Provenance {
  const input = parsed.input as string;
  const networkTools = optedInNetworkTools(parsed.opts, target.kind === "dmg");
  const prov: Provenance = {
    artifact: { path: input, kind: target.kind, sha256Basis: "unavailable" },
    network: networkTools.length > 0 ? "may-contact-apple" : "offline",
    networkTools,
    networkNote:
      networkTools.length > 0
        ? `Opted in via flag: ${networkTools.join(" and ")} may contact Apple. shipcheck itself has no network client.`
        : "shipcheck contains no network client and did not run spctl or stapler. Other local host tools (codesign, xattr, lipo, otool, file) are not sandboxed; offline is by design, not OS-enforced.",
    extraction: target.kind === "zip" && target.zip?.extractedFiles !== undefined ? "confined-pure-ts-extract-to-private-temp" : "none",
    hostTools: usedToolPaths(),
    toolEnvironment: toolEnvironmentNote(),
    generatedBy: `shipcheck ${VERSION}`,
    limits: { nativeImages: MAX_MACHO_ANALYZED, nativeToolOutputKiB: 1024, updateMetadataFiles: 8, updateMetadataBytes: MAX_UPDATE_METADATA_BYTES },
  };
  if (target.kind === "zip" || target.kind === "dmg") {
    try {
      prov.artifact.realPath = realpathSync(input);
    } catch {
      // leave unavailable
    }
    if (pin !== undefined) {
      prov.artifact.sizeBytes = pin.identity.size;
      prov.artifact.modified = new Date(pin.identity.mtimeMs).toISOString();
      if (changed) {
        prov.artifact.sha256Basis = "changed-during-audit";
      } else {
        prov.artifact.sha256 = pin.sha256;
        prov.artifact.sha256Basis = "file-stream";
      }
    }
    if (target.kind === "zip") prov.limits = { ...prov.limits, ...parsed.zipLimits };
    return prov;
  }

  // Bundle directory: audited in place, so record what was audited. A path
  // inside the bundle (Contents/, an executable) is NOT the artifact hashed.
  try {
    prov.artifact.realPath = realpathSync(input);
    prov.artifact.modified = statSync(input).mtime.toISOString();
  } catch {
    // leave unavailable
  }
  if (bundleReal !== undefined) {
    prov.artifact.auditedBundle = bundleReal;
    prov.artifact.sha256Basis = "not-applicable-directory";
  }
  return prov;
}

async function loadHtmlRenderer(): Promise<(report: Report) => string> {
  // Owned by the HTML renderer lane. Loaded lazily so the CLI builds and runs
  // for every other format before that file lands.
  const spec = "./render/html.js";
  try {
    const mod = (await import(spec)) as { renderHtml?: (report: Report) => string };
    if (typeof mod.renderHtml !== "function") throw new Error("renderHtml export missing");
    return mod.renderHtml;
  } catch (e) {
    throw new Error(`HTML renderer unavailable (${e instanceof Error ? e.message : String(e)}).`);
  }
}

if (require.main === module) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((e) => {
      process.stderr.write(`shipcheck: internal error: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
      process.exitCode = 5;
    });
}

export { VERSION, USAGE };
