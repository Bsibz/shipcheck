// Markdown renderer — the format humans paste into review tickets.

import { ORDER, unresolvedSummary, type Report, type Status } from "../report.js";

const BADGES: Record<Status, string> = {
  pass: "✅ pass",
  info: "ℹ️ info",
  warn: "⚠️ warn",
  fail: "❌ fail",
  unknown: "❓ unknown",
  skip: "⏭️ skip",
};

export function renderMarkdown(report: Report): string {
  const out: string[] = [];
  const t = report.target;

  const unresolved = unresolvedSummary(report.summary);
  // Green is reserved for a clean receipt with nothing unresolved. Unknowns use the same purple family as the HTML report.
  const emoji = report.verdict === "failures" ? "🔴" : report.verdict === "warnings" ? "🟡" : unresolved.total > 0 ? "🟣" : "🟢";
  const verdict = unresolved.total > 0 ? `${report.verdict} · unknown=${unresolved.unknown} skip=${unresolved.skip} (not passes)` : report.verdict;
  out.push(`# shipcheck report ${emoji}`);
  out.push("");
  out.push(`- **Target:** \`${t.input}\` (${t.kind})`);
  out.push(`- **Bundle:** ${t.bundleName ?? "(none)"}${t.otherBundles !== undefined ? ` (others ignored: ${t.otherBundles.length})` : ""}`);
  out.push(`- **Verdict:** ${verdict}`);
  const a = report.provenance?.artifact;
  if (a !== undefined) out.push(`- **Artifact:** ${a.kind}${a.sizeBytes !== undefined ? `, ${a.sizeBytes} bytes` : ""}${a.sha256 !== undefined ? `, sha256 \`${a.sha256}\`` : ""} · network: ${report.provenance.network}`);
  if (report.basisSummary !== undefined) out.push(`- **Evidence:** ${report.basisSummary.verified} verified · ${report.basisSummary.inferred} inferred · ${report.basisSummary.unknown} unknown`);
  out.push(`- **When:** ${report.timestamp}`);
  out.push(`- **Tool:** shipcheck ${report.version} · macOS ${escapeMd(report.runtime.macos)} · ${report.runtime.arch}`);
  out.push("");
  for (const note of report.notes) out.push(`> ${escapeInline(note)}`);
  if (report.notes.length > 0) out.push("");

  const groups = new Map<string, typeof report.findings>();
  for (const f of report.findings) {
    const list = groups.get(f.group) ?? [];
    list.push(f);
    groups.set(f.group, list);
  }

  for (const group of groups.keys()) {
    const findings = groups.get(group) ?? [];
    out.push(`## ${group} (${findings.length})`);
    out.push("");
    for (const f of findings) {
      const tag = f.basis !== undefined && f.basis !== "verified" ? ` _(${f.basis})_` : "";
      out.push(`### ${BADGES[f.status]} \`${f.id}\`${tag}`);
      out.push("");
      out.push(escapeInline(f.detail));
      if ((f.evidence ?? []).length > 0) {
        out.push("");
        const longest = Math.max(0, ...(f.evidence ?? []).map((e) => (e.match(/`+/g) ?? []).reduce((m, r) => Math.max(m, r.length), 0)));
        const fence = "`".repeat(Math.max(3, longest + 1));
        out.push(fence);
        for (const e of f.evidence ?? []) out.push(e);
        out.push(fence);
      }
      if (f.hint !== undefined) {
        out.push("");
        out.push(`*hint:* ${escapeInline(f.hint)}`);
      }
      out.push("");
    }
  }

  const parts = ORDER.filter((s) => (report.summary[s] ?? 0) > 0).map((s) => `${report.summary[s]} ${s}`);
  out.push(`## Summary`);
  out.push("");
  out.push(`${parts.join(" · ")} — verdict: **${report.verdict}**`);
  out.push("");
  return out.join("\n");
}

function escapeInline(s: string): string {
  return s.replace(/[\\`*_<>\[\]|]/g, (c) => `\\${c}`).replace(/\n/g, " ");
}

function escapeMd(s: string): string {
  return s.replace(/[|]/g, "\\|");
}
