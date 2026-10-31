// Regression coverage for ad-hoc signature scope.
//
// Every arm64 Mach-O the linker emits carries an ad-hoc signature. `codesign -d`
// on an UNSIGNED .app reports that inner signature (flags=adhoc,linker-signed,
// Sealed Resources=none, no Authority), and --verify --strict fails. That is not
// an ad-hoc-signed app. The fixtures are captured real output; only the path is
// normalized. Fake host tools emit data only; artifact code is never run.

import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";

import { parseDisplay, classifyAdhoc } from "../dist/codesign.js";
import { readAppStructure } from "../dist/bundle.js";
import { runSignatures } from "../dist/checks-identity.js";
import { Collector, defaultOptions } from "../dist/report.js";
import { setToolOverride } from "../dist/proc.js";
import { renderText } from "../dist/render/text.js";
import { renderMarkdown } from "../dist/render/markdown.js";
import { renderHtml } from "../dist/render/html.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures", "data");
const LINKER = readFileSync(join(FIX, "codesign-display-linker-signed.txt"), "utf8");
const ADHOC_BUNDLE = readFileSync(join(FIX, "codesign-display-adhoc-bundle.txt"), "utf8");
const UNSIGNED = readFileSync(join(FIX, "codesign-display-unsigned.txt"), "utf8");

function sandbox(t) {
  const p = mkdtempSync(join(tmpdir(), "sc-sign-scope-"));
  t.after(() => rmSync(p, { recursive: true, force: true }));
  return p;
}

/** Skeleton .app; `signedBundle` adds the Contents/_CodeSignature a real bundle signature produces. */
function makeApp(t, { signedBundle = false } = {}) {
  const dir = sandbox(t);
  const bundle = join(dir, "Demo.app");
  mkdirSync(join(bundle, "Contents", "MacOS"), { recursive: true });
  mkdirSync(join(bundle, "Contents", "Resources"), { recursive: true });
  writeFileSync(
    join(bundle, "Contents", "Info.plist"),
    `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.test.demo</string>
  <key>CFBundleName</key><string>Demo</string>
  <key>CFBundleExecutable</key><string>Demo</string>
  <key>CFBundleShortVersionString</key><string>1.2.3</string>
  <key>CFBundleVersion</key><string>45</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>`,
  );
  const exe = join(bundle, "Contents", "MacOS", "Demo");
  writeFileSync(exe, "#!/bin/sh\nexit 0\n");
  chmodSync(exe, 0o755);
  if (signedBundle) {
    mkdirSync(join(bundle, "Contents", "_CodeSignature"), { recursive: true });
    writeFileSync(join(bundle, "Contents", "_CodeSignature", "CodeResources"), "<plist><dict/></plist>");
  }
  return join(bundle);
}

const sq = (s) => `'${s.replace(/'/g, "'\\''")}'`;

/**
 * Fake codesign answering shipcheck's three call shapes. Display facts come from
 * a file so a fixture can be used verbatim.
 */
function fakeCodesign(t, { display, verifyExit = 0, verifyText = "Demo.app: valid on disk\nDemo.app: satisfies its Designated Requirement", requirementExit = 0 } = {}) {
  const dir = sandbox(t);
  const displayPath = join(dir, "display.txt");
  writeFileSync(displayPath, display);
  const path = join(dir, "codesign");
  writeFileSync(
    path,
    `#!/bin/sh
case "$*" in
  *-R=*) [ ${requirementExit} -ne 0 ] && echo 'test-requirement: code failed to satisfy specified code requirement(s)' >&2; exit ${requirementExit};;
  *--verify*) cat >&2 <<'SHIPCHECK_VERIFY_EOF'
${verifyText}
SHIPCHECK_VERIFY_EOF
  exit ${verifyExit};;
  *--entitlements*) exit 0;;
  *"-d --verbose=4"*) cat ${sq(displayPath)} >&2; exit 0;;
esac
exit 0`,
  );
  chmodSync(path, 0o755);
  return path;
}

function runWith(appPath, codesignPath) {
  const app = readAppStructure(appPath);
  const ctx = {
    app,
    target: { kind: "bundle", input: app.bundlePath },
    opts: { ...defaultOptions },
    params: { timeoutMs: 20_000 },
    collector: new Collector(),
    toolMissing: new Set(),
    issues: [],
  };
  setToolOverride("codesign", { path: codesignPath });
  try {
    runSignatures(ctx);
  } finally {
    setToolOverride("codesign", undefined);
  }
  return ctx;
}

// ---- parsing: scope is a fact, not a guess ------------------------------------

test("real linker-only output parses as an adhoc flag that is linker-signed, with no sealed resources", () => {
  const info = parseDisplay(LINKER, "", 0);
  assert.equal(info.notSigned, false);
  assert.equal(info.signatureAdhoc, true);
  assert.equal(info.linkerSigned, true);
  assert.equal(info.sealedResources, false);
  assert.equal(info.teamIdentifier, "not set");
  assert.deepEqual(info.authority, []);
  assert.deepEqual(info.flagNames, ["adhoc", "linker-signed"]);
});

test("real ad-hoc-signed bundle output has the adhoc flag, sealed resources and no linker flag", () => {
  const info = parseDisplay(ADHOC_BUNDLE, "", 0);
  assert.equal(info.signatureAdhoc, true);
  assert.equal(info.linkerSigned, false);
  assert.equal(info.sealedResources, true);
  assert.equal(info.teamIdentifier, "not set");
});

test("classifyAdhoc separates bundle ad-hoc, linker-only and unknown scope", () => {
  const link = parseDisplay(LINKER, "", 0);
  const adhoc = parseDisplay(ADHOC_BUNDLE, "", 0);
  const unsigned = parseDisplay(UNSIGNED, "", 1);
  const noSealLine = parseDisplay(ADHOC_BUNDLE.replace(/^Sealed Resources.*\n/m, ""), "", 0);

  assert.equal(classifyAdhoc(link, false), "linker-only");
  assert.equal(classifyAdhoc(adhoc, true), "bundle-adhoc");
  assert.equal(classifyAdhoc(unsigned, false), "none");
  assert.equal(classifyAdhoc(noSealLine, true), "unknown", "an adhoc flag without a sealed-resources verdict is not guessed");
  // A linker-signed CodeDirectory never becomes a bundle signature, even next to stale resources.
  assert.equal(classifyAdhoc(link, true), "linker-only");
});

// ---- findings: the two states stay distinct -----------------------------------

test("an unsigned bundle with a linker-only Mach-O signature is reported as unsigned, never as an ad-hoc-signed app", (t) => {
  const ctx = runWith(makeApp(t), fakeCodesign(t, { display: LINKER, verifyExit: 1, verifyText: "Demo.app: code has no resources but signature indicates they must be present" }));

  const presence = ctx.collector.byId("sign.presence");
  assert.equal(presence.status, "fail");
  assert.equal(presence.basis, "verified");
  assert.match(presence.detail, /not code-signed/);
  assert.match(presence.detail, /linker-generated ad-hoc signature/);
  assert.match(presence.detail, /not an ad-hoc-signed app/);
  assert.ok(presence.evidence.some((e) => /flags=\(adhoc,linker-signed\)/.test(e)));
  assert.ok(presence.evidence.some((e) => /Sealed Resources=none/.test(e)));

  const link = ctx.collector.byId("sign.linker-signature");
  assert.equal(link.status, "warn");
  assert.equal(link.basis, "verified");
  assert.match(link.detail, /linker-generated ad-hoc signature only/);

  assert.equal(ctx.collector.byId("sign.validity").status, "fail");
  assert.equal(ctx.collector.byId("sign.resources").status, "fail");
  assert.equal(ctx.collector.byId("sign.adhoc"), undefined, "no ad-hoc-app claim for an unsigned bundle");
  assert.equal(ctx.collector.byId("sign.author"), undefined);
  assert.doesNotMatch(JSON.stringify(ctx.collector.findings), /Signature is ad-hoc/);
});

test("a bundle actually signed ad-hoc still warns as ad-hoc (unchanged)", (t) => {
  const ctx = runWith(makeApp(t, { signedBundle: true }), fakeCodesign(t, { display: ADHOC_BUNDLE }));

  const adhoc = ctx.collector.byId("sign.adhoc");
  assert.equal(adhoc.status, "warn");
  assert.match(adhoc.detail, /Signature is ad-hoc/);
  assert.equal(ctx.collector.byId("sign.linker-signature"), undefined);
  assert.equal(ctx.collector.byId("sign.presence"), undefined);
  assert.equal(ctx.collector.byId("sign.validity").status, "pass");
});

test("a truly unsigned bundle stays unsigned and gains no linker finding", (t) => {
  const ctx = runWith(makeApp(t), fakeCodesign(t, { display: UNSIGNED, verifyExit: 1 }));

  assert.equal(ctx.collector.byId("sign.presence").status, "fail");
  assert.equal(ctx.collector.byId("sign.validity").status, "skip");
  assert.equal(ctx.collector.byId("sign.adhoc"), undefined);
  assert.equal(ctx.collector.byId("sign.linker-signature"), undefined);
});

test("an adhoc flag with no sealed-resources verdict is UNKNOWN, not an ad-hoc-app claim", (t) => {
  const display = ADHOC_BUNDLE.replace(/^Sealed Resources.*\n/m, "");
  const ctx = runWith(makeApp(t, { signedBundle: true }), fakeCodesign(t, { display }));

  const adhoc = ctx.collector.byId("sign.adhoc");
  assert.equal(adhoc.status, "unknown");
  assert.equal(adhoc.basis, "unknown");
  assert.equal(ctx.collector.byId("sign.linker-signature"), undefined);
  assert.doesNotMatch(JSON.stringify(ctx.collector.findings), /Signature is ad-hoc/);
});

test("Developer ID signing behavior is unchanged (author/team verified, no adhoc or linker finding)", (t) => {
  const display = `Identifier=com.test.demo
Format=bundle with Mach-O thin (arm64)
CodeDirectory v=20400 size=262 flags=0x10000(runtime) hashes=2+3 location=embedded
Authority=Developer ID Application: Acme Corp (ABCDE12345)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Oct 1, 2026 at 12:00:00
TeamIdentifier=ABCDE12345
Sealed Resources version=2 rules=13 files=0
`;
  const ctx = runWith(makeApp(t, { signedBundle: true }), fakeCodesign(t, { display }));

  assert.equal(ctx.collector.byId("sign.author").status, "pass");
  assert.equal(ctx.collector.byId("sign.author").basis, "verified");
  assert.equal(ctx.collector.byId("sign.team").status, "pass");
  assert.equal(ctx.collector.byId("sign.validity").status, "pass");
  assert.equal(ctx.collector.byId("sign.adhoc"), undefined);
  assert.equal(ctx.collector.byId("sign.linker-signature"), undefined);
});

// ---- text / Markdown / HTML / JSON agree --------------------------------------

test("text, Markdown and HTML carry the same linker-only wording as the JSON findings", (t) => {
  const ctx = runWith(makeApp(t), fakeCodesign(t, { display: LINKER, verifyExit: 1, verifyText: "Demo.app: code has no resources but signature indicates they must be present" }));
  const findings = ctx.collector.findings;
  const report = {
    tool: "shipcheck",
    version: "0.2.0",
    reportVersion: 1,
    timestamp: "2026-10-31T00:00:00.000Z",
    runtime: { macos: "Darwin 27.2.0 (test)", arch: "arm64", node: "v24" },
    target: { kind: "bundle", input: "/tmp/Demo.app", bundlePath: "/tmp/Demo.app", bundleName: "Demo.app" },
    options: { ...defaultOptions },
    notes: [],
    findings,
    summary: ctx.collector.summary(),
    verdict: ctx.collector.worst(),
  };

  const json = JSON.stringify(findings);
  assert.match(json, /linker-generated ad-hoc signature/);
  assert.equal(findings.filter((f) => f.id === "sign.adhoc").length, 0);

  const text = renderText(report, true);
  assert.match(text, /sign\.linker-signature/);
  assert.doesNotMatch(text, /Signature is ad-hoc/);

  const md = renderMarkdown(report);
  assert.match(md, /`sign\.linker-signature`/);
  assert.doesNotMatch(md, /Signature is ad-hoc/);

  const html = renderHtml(report);
  assert.match(html, /sign\.linker-signature/);
  assert.doesNotMatch(html, /Signature is ad-hoc/);

  // One verdict across surfaces: this bundle fails.
  assert.equal(report.verdict, "failures");
  assert.match(text, /VERDICT FAILURES/);
  assert.match(md, /^- \*\*Verdict:\*\* failures$/m);
  assert.match(html, /<section class="verdict v-fail"/);
});
