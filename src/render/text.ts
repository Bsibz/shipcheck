// Plain-text renderer: grep-friendly, CI-log-friendly, no color codes.

import { ORDER, unresolvedSummary, type Report, type Status } from "../report.js";

const GLYPHS: Record<Status, string> = {
  pass: "[ ok ]",
  info: "[inf ]",
  warn: "[warn]",
  fail: "[FAIL]",
  unknown: "[ ???]",
  skip: "[skip]",
};

export function renderText(report: Report, hints: boolean): string {
  const out: string[] = [];
  const t = report.target;

  out.push(`shipcheck ${report.version} — ${t.kind === "zip" ? "release zip" : t.kind === "dmg" ? "disk image (container only)" : "bundle"} → ${t.bundlePath ?? t.input}`);
  out.push(`found .app bundle: ${t.bundleName ?? "(none)"}`);
  out.push(`macOS ${report.runtime.macos.split("(")[0]?.trim() ?? ""} · ${report.runtime.arch} · node ${report.runtime.node}`);
  out.push("");
  for (const note of report.notes) out.push(`note: ${note}`);
  if (report.notes.length > 0) out.push("");

  const groups = new Map<string, typeof report.findings>();
  for (const f of report.findings) {
    const list = groups.get(f.group) ?? [];
    list.push(f);
    groups.set(f.group, list);
  }

  for (const group of groups.keys()) {
    out.push(group.toUpperCase());
    for (const f of groups.get(group) ?? []) {
      const tag = f.basis !== undefined && f.basis !== "verified" ? ` {${f.basis}}` : "";
      out.push(`  ${GLYPHS[f.status]} ${f.id}${tag}: ${f.detail}`);
      for (const e of f.evidence ?? []) out.push(`         · ${e}`);
      if (hints && f.hint !== undefined) out.push(`         hint: ${f.hint}`);
    }
    out.push("");
  }

  const parts = ORDER.filter((s) => (report.summary[s] ?? 0) > 0).map((s) => `${s}=${report.summary[s]}`);
  const b = report.basisSummary;
  if (b !== undefined) out.push(`EVIDENCE verified=${b.verified} inferred=${b.inferred} unknown=${b.unknown}`);
  const a = report.provenance?.artifact;
  if (a !== undefined) out.push(`ARTIFACT ${a.kind} ${a.sha256 !== undefined ? `sha256=${a.sha256}` : `sha256=n/a (${a.sha256Basis})`}${a.sizeBytes !== undefined ? ` size=${a.sizeBytes}` : ""}`);
  out.push(`SUMMARY ${parts.join(" ")}`);
  out.push(`VERDICT ${report.verdict.toUpperCase()}`);
  const unresolved = unresolvedSummary(report.summary);
  if (unresolved.total > 0) out.push(`UNRESOLVED unknown=${unresolved.unknown} skip=${unresolved.skip} (not passes)`);
  return out.join("\n") + "\n";
}
