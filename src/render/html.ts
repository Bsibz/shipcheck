// HTML renderer — a standalone, offline, printable report for release reviews.
//
// Self-contained by construction: inline CSS only, no scripts, no fonts, no
// remote assets, and a CSP that forbids loading anything. Every string that
// came from the artifact or a tool (paths, plist values, tool output) is
// treated as untrusted and escaped.
//
// Evidence class comes from the collector's `basis` (VERIFIED / INFERRED /
// UNKNOWN). Reports written before `basis` existed fall back to a
// conservative rule: unknown/skip → UNKNOWN, raw evidence lines → VERIFIED,
// otherwise INFERRED.

import { ORDER, unresolvedSummary, type Basis, type Finding, type Report, type Status } from "../report.js";
import { GROUP } from "../checkscommon.js";

type EvidenceClass = Basis;

const STATUS_LABEL: Record<Status, string> = {
  fail: "Fail",
  warn: "Warn",
  unknown: "Unknown",
  skip: "Skipped",
  info: "Info",
  pass: "Pass",
};

// Glyphs keep status legible without color (print, color-blind readers).
const STATUS_GLYPH: Record<Status, string> = {
  fail: "✕",
  warn: "!",
  unknown: "?",
  skip: "–",
  info: "i",
  pass: "✓",
};

const SEVERITY: Status[] = ["fail", "warn", "unknown", "skip", "info", "pass"];

const EVIDENCE_LABEL: Record<EvidenceClass, string> = {
  verified: "VERIFIED",
  inferred: "INFERRED",
  unknown: "UNKNOWN",
};

export function evidenceClass(f: Finding): EvidenceClass {
  if (f.basis !== undefined) return f.basis;
  if (f.status === "unknown" || f.status === "skip") return "unknown";
  return (f.evidence ?? []).length > 0 ? "verified" : "inferred";
}

export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const e = escapeHtml;

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "x";
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function statusBadge(s: Status): string {
  return `<span class="badge st-${s}"><span class="glyph" aria-hidden="true">${STATUS_GLYPH[s]}</span>${STATUS_LABEL[s]}</span>`;
}

function evidenceBadge(c: EvidenceClass): string {
  return `<span class="ev ev-${c}" title="Evidence class">${EVIDENCE_LABEL[c]}</span>`;
}

function verdictCopy(report: Report): { title: string; sub: string; cls: string } {
  const unresolved = unresolvedSummary(report.summary).total;
  const fails = report.summary.fail ?? 0;
  const warns = report.summary.warn ?? 0;
  if (report.verdict === "failures") {
    return {
      cls: "v-fail",
      title: "Not ready to ship",
      sub: `${plural(fails, "blocking failure")}${warns > 0 ? ` and ${plural(warns, "warning")}` : ""} must be resolved before release.`,
    };
  }
  if (report.verdict === "warnings") {
    return {
      cls: "v-warn",
      title: "Ship with caution",
      sub: `No failures, but ${plural(warns, "warning")} need a deliberate decision.`,
    };
  }
  return {
    cls: unresolved > 0 ? "v-partial" : "v-clean",
    title: unresolved > 0 ? "No failures found — coverage incomplete" : "No failures or warnings",
    sub:
      unresolved > 0
        ? `${unresolved === 1 ? "1 check could not be determined or was skipped" : `${unresolved} checks could not be determined or were skipped`}. Clean is not the same as proven.`
        : "Every executed check passed or reported informational results.",
  };
}

function groupFindings(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = groups.get(f.group) ?? [];
    list.push(f);
    groups.set(f.group, list);
  }
  return groups;
}

function renderFinding(f: Finding, showHint: boolean): string {
  const ev = f.evidence ?? [];
  const cls = evidenceClass(f);
  const parts: string[] = [];
  parts.push(`<article class="finding st-${f.status}" id="f-${e(slug(f.id))}">`);
  parts.push(`<div class="f-head">${statusBadge(f.status)}<code class="f-id">${e(f.id)}</code>${evidenceBadge(cls)}</div>`);
  parts.push(`<p class="f-detail">${e(f.detail)}</p>`);
  if (ev.length > 0) {
    parts.push(
      `<details class="f-ev" open><summary>Evidence (${ev.length} ${ev.length === 1 ? "line" : "lines"})</summary><pre>${ev.map(e).join("\n")}</pre></details>`,
    );
  }
  if (showHint && f.hint !== undefined) {
    parts.push(`<p class="f-hint"><span class="k">Fix</span>${e(f.hint)}</p>`);
  }
  parts.push(`</article>`);
  return parts.join("");
}

function renderActions(report: Report): string {
  const action = report.findings
    .filter((f) => f.status === "fail" || f.status === "warn")
    .sort((a, b) => SEVERITY.indexOf(a.status) - SEVERITY.indexOf(b.status));
  const unresolved = report.findings.filter((f) => f.status === "unknown");
  if (action.length === 0 && unresolved.length === 0) {
    return `<p class="empty">No actions required by the executed checks.</p>`;
  }
  const items = action.map((f, i) => {
    const todo = f.hint !== undefined && report.options.hints ? e(f.hint) : `Review: ${e(f.detail)}`;
    return `<li class="act st-${f.status}"><span class="n">${i + 1}</span><div><div class="act-top">${statusBadge(f.status)}<a href="#f-${e(slug(f.id))}"><code>${e(f.id)}</code></a><span class="grp">${e(f.group)}</span></div><p class="act-do">${todo}</p>${f.hint !== undefined && report.options.hints ? `<p class="act-why">${e(f.detail)}</p>` : ""}</div></li>`;
  });
  const unk = unresolved.map(
    (f) =>
      `<li class="act st-unknown"><span class="n">?</span><div><div class="act-top">${statusBadge("unknown")}<a href="#f-${e(slug(f.id))}"><code>${e(f.id)}</code></a><span class="grp">${e(f.group)}</span></div><p class="act-do">Establish manually: ${e(f.detail)}</p></div></li>`,
  );
  return `<ol class="actions">${items.join("")}${unk.join("")}</ol>`;
}

function renderCoverage(report: Report, groups: Map<string, Finding[]>): string {
  const known = Object.values(GROUP) as string[];
  const names = [...known.filter((g) => groups.has(g)), ...[...groups.keys()].filter((g) => !known.includes(g))];
  const missing = known.filter((g) => !groups.has(g));
  const rows = names.map((g) => {
    const list = groups.get(g) ?? [];
    const count = (s: Status): number => list.filter((f) => f.status === s).length;
    const ev = (c: EvidenceClass): number => list.filter((f) => evidenceClass(f) === c).length;
    const worst = SEVERITY.find((s) => count(s) > 0) ?? "pass";
    const cells = SEVERITY.map((s) => {
      const n = count(s);
      return `<td class="num${n > 0 ? ` has st-${s}` : " zero"}">${n}</td>`;
    }).join("");
    const total = list.length;
    const v = ev("verified");
    const bar =
      total > 0
        ? `<span class="bar" role="img" aria-label="${v} verified, ${ev("inferred")} inferred, ${ev("unknown")} unknown of ${total}"><span class="b-v" style="width:${(v / total) * 100}%"></span><span class="b-i" style="width:${(ev("inferred") / total) * 100}%"></span><span class="b-u" style="width:${(ev("unknown") / total) * 100}%"></span></span>`
        : "";
    return `<tr><th scope="row"><a href="#g-${e(slug(g))}">${e(g)}</a></th><td>${statusBadge(worst)}</td>${cells}<td><span class="evcell">${bar}<span class="evtxt">${v}/${total} verified</span></span></td></tr>`;
  });
  const head = SEVERITY.map((s) => `<th scope="col" class="num">${STATUS_LABEL[s]}</th>`).join("");
  const o = report.options;
  const scope: Array<[string, string]> = [
    ["ASAR depth", o.asarDepth],
    ["Hashes", o.hashes],
    ["Path scan", o.pathsScan],
    ["Universal required", o.universal ? "yes" : "no"],
    ["Stapler validate", o.stapler ? "run" : "not run"],
    ["Fail threshold", o.failOn],
    ["Tool timeout", `${Math.round(o.timeoutMs / 1000)}s`],
  ];
  return [
    `<div class="table-wrap"><table class="cov"><caption class="sr">Check coverage by group</caption><thead><tr><th scope="col">Group</th><th scope="col">Worst</th>${head}<th scope="col">Evidence</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`,
    missing.length > 0
      ? `<p class="missing"><span class="k">Not run</span>${missing.map((g) => `<span class="chip">${e(g)}</span>`).join("")}<span class="muted">No findings were recorded for these groups — treat as UNKNOWN.</span></p>`
      : "",
    `<dl class="scope">${scope.map(([k, v]) => `<div><dt>${e(k)}</dt><dd>${e(v)}</dd></div>`).join("")}</dl>`,
  ].join("");
}

export function renderHtml(report: Report): string {
  const t = report.target;
  const groups = groupFindings(report.findings);
  const v = verdictCopy(report);
  const title = `shipcheck — ${t.bundleName ?? t.input}`;
  // Count from findings so the legend always matches the rows shown.
  const evTotals: Record<EvidenceClass, number> = { verified: 0, inferred: 0, unknown: 0 };
  for (const f of report.findings) evTotals[evidenceClass(f)] += 1;

  const stats = SEVERITY.map(
    (s) =>
      `<div class="stat st-${s}${(report.summary[s] ?? 0) === 0 ? " zero" : ""}"><span class="sv">${report.summary[s] ?? 0}</span><span class="sl"><span class="glyph" aria-hidden="true">${STATUS_GLYPH[s]}</span>${STATUS_LABEL[s]}</span></div>`,
  ).join("");

  const meta: Array<[string, string]> = [
    ["Input", `${t.input} (${t.kind === "zip" ? "release zip" : t.kind === "dmg" ? "disk image; container only" : "app bundle"})`],
    ["Audited bundle", t.bundleName ?? "(none found)"],
  ];
  if (t.bundlePath !== undefined && t.bundlePath !== t.input) meta.push(["Bundle path", t.bundlePath]);
  if (t.otherBundles !== undefined && t.otherBundles.length > 0) {
    meta.push(["Other bundles (not audited)", t.otherBundles.join(", ")]);
  }
  meta.push(["Generated", report.timestamp]);
  meta.push(["Host", `macOS ${report.runtime.macos} · ${report.runtime.arch} · node ${report.runtime.node}`]);

  const groupSections = [...groups.entries()]
    .map(([g, list]) => {
      const sorted = [...list].sort((a, b) => SEVERITY.indexOf(a.status) - SEVERITY.indexOf(b.status));
      const counts = ORDER.filter((s) => list.some((f) => f.status === s))
        .map((s) => `${list.filter((f) => f.status === s).length} ${STATUS_LABEL[s].toLowerCase()}`)
        .join(" · ");
      return `<section class="group" id="g-${e(slug(g))}" aria-labelledby="gh-${e(slug(g))}"><h3 id="gh-${e(slug(g))}">${e(g)} <span class="muted">${e(counts)}</span></h3>${sorted.map((f) => renderFinding(f, report.options.hints)).join("")}</section>`;
    })
    .join("");

  const pv = report.provenance as Report["provenance"] | undefined;
  let provenance = "";
  if (pv !== undefined) {
    const a = pv.artifact;
    const rows: Array<[string, string]> = [["Artifact", `${a.path} (${a.kind})`]];
    if (a.realPath !== undefined && a.realPath !== a.path) rows.push(["Resolved path", a.realPath]);
    rows.push([
      "SHA-256",
      a.sha256 ?? (a.sha256Basis === "not-applicable-directory" ? "n/a — directories are not hashed as a whole" : "unavailable"),
    ]);
    if (a.sizeBytes !== undefined) rows.push(["Size", `${a.sizeBytes.toLocaleString("en-US")} bytes`]);
    if (a.modified !== undefined) rows.push(["Modified", a.modified]);
    rows.push(["Network", `${pv.network} — ${pv.networkNote}`]);
    rows.push(["Extraction", pv.extraction]);
    for (const [tool, path] of Object.entries(pv.hostTools ?? {})) rows.push([`Tool · ${tool}`, path]);
    if (pv.toolEnvironment !== undefined) rows.push(["Tool environment", pv.toolEnvironment]);
    for (const [k, n] of Object.entries(pv.limits ?? {})) rows.push([`Limit · ${k}`, String(n)]);
    rows.push(["Generated by", pv.generatedBy]);
    provenance = `<section aria-labelledby="h-prov"><h2 id="h-prov">Provenance</h2><dl class="meta prov">${rows.map(([k, val]) => `<div${k === "SHA-256" || k === "Network" ? ' class="wide"' : ""}><dt>${e(k)}</dt><dd>${e(val)}</dd></div>`).join("")}</dl></section>`;
  }

  const notes =
    report.notes.length > 0
      ? `<section aria-labelledby="h-notes"><h2 id="h-notes">Run notes</h2><ul class="notes">${report.notes.map((n) => `<li>${e(n)}</li>`).join("")}</ul></section>`
      : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="generator" content="shipcheck ${e(report.version)}">
<title>${e(title)}</title>
<style>${CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to report</a>
<header class="top">
  <div class="wrap">
    <div class="brand"><span class="mark" aria-hidden="true">◆</span>shipcheck <span class="muted">${e(report.version)} · report v${e(report.reportVersion)}</span></div>
    <h1>${e(t.bundleName ?? t.input)}</h1>
  </div>
</header>
<main id="main" class="wrap">
  <section class="verdict ${v.cls}" aria-labelledby="h-verdict">
    <div class="v-text">
      <p class="eyebrow">Verdict · <code>${e(report.verdict)}</code></p>
      <h2 id="h-verdict">${e(v.title)}</h2>
      <p>${e(v.sub)}</p>
    </div>
    <div class="stats" role="list" aria-label="Findings by status">${stats.replace(/<div class="stat/g, '<div role="listitem" class="stat')}</div>
  </section>

  <dl class="meta">${meta.map(([k, val]) => `<div><dt>${e(k)}</dt><dd>${e(val)}</dd></div>`).join("")}</dl>

  <section aria-labelledby="h-actions">
    <h2 id="h-actions">Actions</h2>
    ${renderActions(report)}
  </section>

  <section aria-labelledby="h-cov">
    <h2 id="h-cov">Coverage</h2>
    <p class="legend">
      <span>${evidenceBadge("verified")} directly observed in tool or filesystem output · ${evTotals.verified}</span>
      <span>${evidenceBadge("inferred")} concluded indirectly, not directly observed · ${evTotals.inferred}</span>
      <span>${evidenceBadge("unknown")} undetermined or skipped · ${evTotals.unknown}</span>
    </p>
    ${renderCoverage(report, groups)}
  </section>

  ${provenance}

  ${notes}

  <section aria-labelledby="h-findings">
    <h2 id="h-findings">Findings</h2>
    ${groupSections || `<p class="empty">No findings recorded.</p>`}
  </section>
</main>
<footer class="wrap foot">
  <p>Generated by shipcheck ${e(report.version)} as a read-only audit. This report file is self-contained and loads no external resources.</p>
</footer>
</body>
</html>
`;
}

const CSS = `
:root{
  --bg:#f6f7f9;--panel:#fff;--ink:#14171c;--ink2:#4a525e;--mute:#6b7380;--line:#e1e4e9;--soft:#eef0f3;
  --fail:#b42318;--fail-bg:#fdecea;--warn:#9a5b00;--warn-bg:#fff4dc;--unk:#5b3fb5;--unk-bg:#efeafc;
  --skip:#5e6672;--skip-bg:#eceef1;--info:#1d5fa8;--info-bg:#e7f0fb;--pass:#1a7a43;--pass-bg:#e5f5ec;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
  color-scheme:light dark;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0e1116;--panel:#161a21;--ink:#e8ebf0;--ink2:#b3bac5;--mute:#8a93a0;--line:#272d37;--soft:#1d222a;
  --fail:#ff7b72;--fail-bg:#3a1714;--warn:#f0b54a;--warn-bg:#352611;--unk:#b9a3ff;--unk-bg:#271f42;
  --skip:#9aa3af;--skip-bg:#232830;--info:#79b4ff;--info-bg:#132840;--pass:#56d38a;--pass-bg:#112d1e;
}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 var(--sans)}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
code,pre{font-family:var(--mono);font-size:.86em}
a{color:inherit;text-decoration-color:var(--line);text-underline-offset:2px}
a:hover{text-decoration-color:currentColor}
a:focus-visible,summary:focus-visible{outline:2px solid var(--info);outline-offset:2px;border-radius:3px}
.skip{position:absolute;left:-9999px}.skip:focus{left:12px;top:12px;background:var(--panel);padding:6px 10px;z-index:2}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.muted{color:var(--mute);font-weight:400}
.top{border-bottom:1px solid var(--line);background:var(--panel);padding:18px 0 16px}
.brand{font:600 12px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--ink2)}
.mark{color:var(--info);margin-right:6px}
h1{margin:8px 0 0;font-size:22px;font-weight:650;letter-spacing:-.01em;overflow-wrap:anywhere}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink2);margin:36px 0 12px;font-weight:650}
h3{font-size:16px;margin:24px 0 10px;text-transform:capitalize}
h3 .muted{font-size:13px;text-transform:none;margin-left:6px}
main section{break-inside:auto}
.verdict{margin-top:24px;background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--vc);border-radius:10px;padding:20px 22px;display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center}
.verdict h2{margin:2px 0 4px;font-size:24px;letter-spacing:-.01em;text-transform:none;color:var(--vc)}
.verdict p{margin:0;color:var(--ink2)}
.verdict .eyebrow{font:600 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--mute)}
.v-fail{--vc:var(--fail)}.v-warn{--vc:var(--warn)}.v-partial{--vc:var(--unk)}.v-clean{--vc:var(--pass)}
.stats{display:grid;grid-template-columns:repeat(6,minmax(62px,1fr));gap:6px}
.stat{background:var(--sbg);border-radius:8px;padding:8px 10px;text-align:center;color:var(--sc)}
.stat.zero{background:var(--soft);color:var(--mute)}
.sv{display:block;font:650 22px/1.1 var(--mono)}
.sl{font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.st-fail{--sc:var(--fail);--sbg:var(--fail-bg)}.st-warn{--sc:var(--warn);--sbg:var(--warn-bg)}
.st-unknown{--sc:var(--unk);--sbg:var(--unk-bg)}.st-skip{--sc:var(--skip);--sbg:var(--skip-bg)}
.st-info{--sc:var(--info);--sbg:var(--info-bg)}.st-pass{--sc:var(--pass);--sbg:var(--pass-bg)}
.glyph{display:inline-block;width:1.1em;font-weight:700;font-family:var(--mono)}
.badge{display:inline-flex;align-items:center;gap:2px;padding:1px 8px 1px 6px;border-radius:999px;background:var(--sbg);color:var(--sc);font-size:12px;font-weight:600;white-space:nowrap}
.ev{font:600 10.5px/1 var(--mono);letter-spacing:.06em;padding:3px 6px;border-radius:4px;border:1px solid;white-space:nowrap}
.ev-verified{color:var(--pass);border-color:var(--pass)}
.ev-inferred{color:var(--ink2);border-color:var(--line);border-style:dashed}
.ev-unknown{color:var(--unk);border-color:var(--unk)}
.meta,.scope{display:flex;flex-wrap:wrap;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:16px 0 0}
.meta div,.scope div{flex:1 1 220px;background:var(--panel);padding:10px 14px;min-width:0}
dt{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mute)}
dd{margin:2px 0 0;font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
.scope{margin-top:12px}.meta .wide{flex-basis:100%}.scope div{flex-basis:130px}
.actions{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.act{display:grid;grid-template-columns:28px 1fr;gap:12px;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--sc);border-radius:8px;padding:12px 14px;break-inside:avoid}
.act .n{font:650 13px/24px var(--mono);color:var(--sc);text-align:center;background:var(--sbg);border-radius:6px;height:24px}
.act-top{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.act-top code{font-weight:600}
.grp{font-size:12px;color:var(--mute);text-transform:capitalize}
.act-do{margin:6px 0 0;font-weight:550;overflow-wrap:anywhere}
.act-why{margin:2px 0 0;color:var(--ink2);font-size:14px;overflow-wrap:anywhere}
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:8px;padding:14px;color:var(--ink2);margin:0}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;color:var(--ink2);font-size:13px;margin:0 0 12px}
.legend>span{display:inline-flex;align-items:center;gap:6px}
.table-wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
tbody tr:last-child>*{border-bottom:0}
thead th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mute);font-weight:600;background:var(--soft)}
tbody th{font-weight:600;text-transform:capitalize}
.num{text-align:right;font-family:var(--mono)}
td.zero{color:var(--line)}td.has{color:var(--sc);font-weight:700}
.evcell{display:inline-flex;align-items:center;gap:10px}
.bar{display:inline-flex;width:84px;height:6px;border-radius:3px;overflow:hidden;background:var(--soft)}
.b-v{background:var(--pass)}.b-i{background:var(--mute);opacity:.45}.b-u{background:var(--unk)}
.evtxt{font-size:12px;color:var(--mute);font-family:var(--mono)}
.missing{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:12px 0 0;font-size:13px}
.chip{background:var(--unk-bg);color:var(--unk);border-radius:4px;padding:1px 7px;font-family:var(--mono);font-size:12px}
.k{font:600 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--mute);margin-right:8px}
.notes{margin:0;padding-left:18px;color:var(--ink2)}
.finding{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--sc);border-radius:8px;padding:12px 14px;margin:0 0 8px;break-inside:avoid}
.f-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.f-id{font-weight:600;overflow-wrap:anywhere}
.f-head .ev{margin-left:auto}
.f-detail{margin:6px 0 0;overflow-wrap:anywhere}
.f-hint{margin:8px 0 0;font-size:14px;color:var(--ink2);overflow-wrap:anywhere}
.f-ev{margin-top:8px}
.f-ev summary{cursor:pointer;font-size:12.5px;color:var(--ink2)}
pre{margin:6px 0 0;padding:10px 12px;background:var(--soft);border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;line-height:1.45}
.foot{color:var(--mute);font-size:12.5px;padding-top:24px;padding-bottom:40px;border-top:1px solid var(--line);margin-top:40px}
@media (max-width:760px){
  .wrap{padding:0 14px}
  .verdict{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(3,1fr)}
  .f-head .ev{margin-left:0}
}
@media print{
  :root{--bg:#fff;--panel:#fff;--ink:#000;--ink2:#333;--mute:#555;--line:#ccc;--soft:#f3f3f3;color-scheme:light}
  body{font-size:11pt}
  .wrap{max-width:none;padding:0}
  .top{border:0;padding:0 0 8px}
  .skip{display:none}
  a{text-decoration:none}
  .verdict,.finding,.act,.table-wrap,.meta,.scope{box-shadow:none}
  .f-ev>summary{list-style:none}
  h2{break-after:avoid}h3{break-after:avoid}
  .table-wrap{overflow:visible}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
`;
