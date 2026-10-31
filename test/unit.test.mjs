import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";

import { parsePlistXml, getString } from "../dist/plist.js";
import { parseDisplay } from "../dist/codesign.js";
import { parseLipoInfo, parseFileArchOutput } from "../dist/arch.js";
import { parseOtoolL } from "../dist/native.js";
import { renderText } from "../dist/render/text.js";
import { renderMarkdown as renderMd } from "../dist/render/markdown.js";
import { renderHtml } from "../dist/render/html.js";
import { clampToExitCode } from "../dist/cli.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures", "data");

// ---- plist ------------------------------------------------------------------

test("plist parser handles a real Apple Info.plist with attributes on <plist>", () => {
  const xml = readFileSync("/Applications/Ollama.app/Contents/Info.plist", "utf8");
  const r = parsePlistXml(xml);
  assert.equal(r.ok, true);
  const dict = r.value;
  assert.equal(getString(dict, "CFBundleIdentifier"), "com.electron.ollama");
  assert.equal(getString(dict, "CFBundleShortVersionString"), "0.40.11");
  assert.equal(getString(dict, "CFBundleExecutable"), "Ollama");
});

test("plist parser reads ElectronAsarIntegrity dicts out of real Info.plists", () => {
  const xml = readFileSync("/Applications/ChatGPT.app/Contents/Info.plist", "utf8");
  const r = parsePlistXml(xml);
  const dict = r.value;
  const integ = dict["ElectronAsarIntegrity"];
  assert.ok(integ);
  const appAsar = integ["Resources/app.asar"];
  assert.match(appAsar.hash, /^[0-9a-f]{64}$/);
});

test("plist parser handles entities, arrays and booleans", () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">
  <dict>
    <key>s</key><string>a &amp; b &lt;tag&gt; &#x274C;</string>
    <key>arr</key><array><string>x</string><true/></array>
    <key>b</key><true/><key>i</key><integer>42</integer>
    <key>bad</key><data>AAAA</data><key>after</key><string>ok</string>
  </dict></plist>`;
  const d = parsePlistXml(xml).value;
  assert.equal(d.s, "a & b <tag> ❌");
  assert.deepEqual(d.arr, ["x", true]);
  assert.equal(d.b, true);
  assert.equal(d.i, 42);
  assert.equal(d.after, "ok");
  assert.equal(d.bad, undefined);
});

// ---- codesign fixtures --------------------------------------------------------

test("display parser extracts the full picture from a notarized Developer ID app", () => {
  const text = readFileSync(join(FIX, "codesign-display-notarized.txt"), "utf8");
  const info = parseDisplay(text, "", 0);
  assert.equal(info.notSigned, false);
  assert.equal(info.signatureAdhoc, false);
  assert.equal(info.hardenedRuntime, true);
  assert.equal(info.teamIdentifier, "3MU9H2V9Y9");
  assert.equal(info.notarizationStapled, true);
  assert.ok(info.timestamp !== undefined);
  assert.ok(info.authority.some((a) => a.startsWith("Developer ID Application:"), info.authority));
});

test("display parser flags unsigned binaries", () => {
  const text = readFileSync(join(FIX, "codesign-display-unsigned.txt"), "utf8");
  const info = parseDisplay(text, "", 1);
  assert.equal(info.notSigned, true);
});

// ---- arch fixtures -------------------------------------------------------------

test("lipo parser reads universal + thin shapes", () => {
  assert.deepEqual(parseLipoInfo("Architectures in the fat file: /p are: x86_64 arm64 "), ["x86_64", "arm64"]);
  assert.deepEqual(parseLipoInfo("Non-fat file: /p is architecture: arm64"), ["arm64"]);
  assert.deepEqual(parseLipoInfo("The architecture\nof /p: x86_64 arm64"), ["x86_64", "arm64"]);
  assert.deepEqual(parseLipoInfo("can't figure out the architecture type of: /p"), []);
});

test("file parser reads universal compact + multiline shapes", () => {
  assert.deepEqual(parseFileArchOutput("Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64:Mach-O 64-bit executable arm64]"), ["x86_64", "arm64"]);
  const multiline = "Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64]\n/p (for architecture x86_64):\tMach-O 64-bit executable x86_64\n/p (for architecture arm64):\tMach-O 64-bit executable arm64";
  assert.deepEqual(parseFileArchOutput(multiline), ["x86_64", "arm64"]);
  assert.deepEqual(parseFileArchOutput("Mach-O 64-bit bundle arm64"), ["arm64"]);
});

// ---- otool fixture ---------------------------------------------------------------

test("otool parser classifies kerberos-like loader targets as system", () => {
  const text = readFileSync(join(FIX, "otool-kerberos.txt"), "utf8");
  const deps = parseOtoolL(text);
  assert.equal(deps.entries.length, 3);
  for (const e of deps.entries) {
    assert.equal(e.cls, "system", e.target);
  }
});

// ---- asar basics (built fresh here, honest tmpdir) -------------------------------

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

test("asar reader parses a freshly built archive + verifies the recorded hash", async () => {
  const { readHeader, verifyHeaderHash, verifyAsarPerFile } = await import("../dist/asar.js");
  const { createHash } = await import("node:crypto");
  const dir = mkdtempSync(join(tmpdir(), "sc-asar-"));
  try {
    const mainContent = Buffer.from("hello ship\t", "utf8"); // 11 bytes at offset 0
    const pkgContent = Buffer.from('{"name":"demo","version":"1.0.0","main":"main.js"}\n', "utf8"); // 36 bytes at offset 11
    const sha = (buf) => createHash("sha256").update(buf).digest("hex");
    const filesJson = JSON.stringify({
      files: {
        "app/main.js": { size: mainContent.length, offset: "0", integrity: { algorithm: "SHA256", hash: sha(mainContent) } },
        "app/package.json": { size: pkgContent.length, offset: "11", integrity: { algorithm: "SHA256", hash: sha(pkgContent) } },
      },
    });
    const jsonBuf = Buffer.from(filesJson, "utf8");
    const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0, 0); return b; };
    // Real asar prologue (verified against ChatGPT.app / Discord):
    //   [0..4)=u32 4 (pickle header)
    //   [4..8)=headerSize
    //   [8..12)=payloadSize  — must equal headerSize - 4 or pickles "disagree"
    //   [12..16)=jsonLen
    //   [16 .. 16+jsonLen)=index JSON
    //   content region starts at headerSize + 8
    const headerSize = 8 + jsonBuf.length;
    const asarBytes = Buffer.concat([
      u32(4),
      u32(headerSize),
      u32(headerSize - 4),
      u32(jsonBuf.length),
      jsonBuf,
      mainContent,
      pkgContent,
    ]);
    const asarPath = join(dir, "app.asar");
    writeFileSync(asarPath, asarBytes);
    const header = readHeader(asarPath);
    assert.ok(header);
    assert.equal(header.files, 2);
    assert.equal(header.jsonLen, jsonBuf.length);
    assert.equal(header.headerSize, headerSize);
    assert.deepEqual(header.sampleFiles, ["app/main.js", "app/package.json"]);

    const recorded = createHash("sha256").update(asarBytes.subarray(16, 16 + jsonBuf.length)).digest("hex");
    assert.equal(verifyHeaderHash(asarPath, recorded).status, "match");
    const bad = verifyHeaderHash(asarPath, "da".repeat(32));
    assert.equal(bad.status, "mismatch");
    // the reader also re-hashes the alternative pickle slice [12 .. headerSize)
    // when the record is wrong — that region = jsonLen u32 + index JSON
    assert.equal(bad.altComputed, sha(asarBytes.subarray(12, 16 + jsonBuf.length)));

    // content region math: both recorded per-file hashes must verify
    const perFile = verifyAsarPerFile(asarPath, 10);
    assert.equal(perFile.attempted, 2);
    assert.equal(perFile.verifiedFiles, 2);
    assert.equal(perFile.mismatchedFiles.length, 0);
    assert.equal(perFile.capReached, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- renderers ---------------------------------------------------------------

const sampleReport = {
  tool: "shipcheck",
  version: "0.1.0",
  reportVersion: 1,
  timestamp: "2026-10-28T03:00:00.000Z",
  runtime: { macos: "Darwin 27.2.0 (test)", arch: "arm64", node: "v24" },
  target: { kind: "bundle", input: "/tmp/Demo.app", bundlePath: "/tmp/Demo.app", bundleName: "Demo.app" },
  options: JSON.parse(`{"failOn":"fail","asarDepth":"header","hashes":"none","universal":false,"pathsScan":"main","stapler":false,"hints":true,"timeoutMs":90000}`),
  notes: [],
  findings: [
    { id: "bundle.identifier", group: "bundle identity", status: "pass", detail: "CFBundleIdentifier: com.demo" },
    { id: "gatekeeper.assess", group: "gatekeeper", status: "fail", detail: "Gatekeeper rejects the app.", evidence: ["spctl: rejected"], hint: "Notarize." },
  ],
  summary: { pass: 1, warn: 0, fail: 1, info: 0, unknown: 0, skip: 0 },
  verdict: "failures",
};

test("text renderer prints statuses, evidence and verdict", () => {
  const text = renderText(sampleReport, true);
  assert.match(text, /\[FAIL\] gatekeeper\.assess: Gatekeeper rejects the app\./);
  assert.match(text, /spctl: rejected/);
  assert.match(text, /hint: Notarize\./);
  assert.match(text, /VERDICT FAILURES/);
});

test("markdown renderer renders a ticket-friendly report", () => {
  const md = renderMd(sampleReport);
  assert.match(md, /# shipcheck report 🔴/);
  assert.match(md, /`gatekeeper\.assess`/);
  assert.match(md, /^- \*\*Verdict:\*\* failures$/m);
});

test("text renderer honours hints-off", () => {
  const text = renderText(sampleReport, false);
  assert.doesNotMatch(text, /hint:/);
});

test("a clean receipt with unknowns is not rendered as a pass", () => {
  const report = {
    ...sampleReport,
    findings: [
      { id: "bundle.identifier", group: "bundle identity", status: "pass", detail: "id present" },
      { id: "gatekeeper.assess", group: "gatekeeper", status: "unknown", basis: "unknown", detail: "Gatekeeper assessment not run." },
    ],
    summary: { pass: 1, warn: 0, fail: 0, info: 0, unknown: 1, skip: 0 },
    verdict: "clean",
  };
  const text = renderText(report, false);
  assert.match(text, /VERDICT CLEAN\nUNRESOLVED unknown=1 skip=0 \(not passes\)/);
  assert.match(text, /\[ \?\?\?\] gatekeeper\.assess/);
  assert.doesNotMatch(text, /\[ ok \] gatekeeper\.assess/);
  const md = renderMd(report);
  assert.match(md, /# shipcheck report 🟣/);
  assert.doesNotMatch(md, /🟢/);
  assert.match(md, /^- \*\*Verdict:\*\* clean · unknown=1 skip=0 \(not passes\)$/m);
  const html = renderHtml(report);
  assert.match(html, /<section class="verdict v-partial"/);
  assert.doesNotMatch(html, /<section class="verdict v-clean"/);
  assert.match(html, /1 check could not be determined or was skipped/);
  assert.doesNotMatch(html, /1 check could not be determined or were skipped/);
  const unknownAt = html.indexOf('id="f-gatekeeper-assess"');
  assert.ok(unknownAt > 0);
  const unknownArticle = html.slice(Math.max(0, unknownAt - 120), unknownAt + 220);
  assert.match(unknownArticle, /st-unknown/);
  assert.doesNotMatch(unknownArticle, /st-pass/);
});

// ---- exit code contract ---------------------------------------------------------

test("exit codes: failures → 2, warnings → 1 by default, 0 when clean", () => {
  assert.equal(clampToExitCode("failures", "fail", sampleReport.options), 2);
  assert.equal(clampToExitCode("warnings", "fail", sampleReport.options), 1);
  assert.equal(clampToExitCode("clean", "fail", sampleReport.options), 0);
  assert.equal(clampToExitCode("warnings", "warn", sampleReport.options), 2);
  assert.equal(clampToExitCode("failures", "warn", sampleReport.options), 2);
  assert.equal(clampToExitCode("warnings", "never", sampleReport.options), 0);
});

test("strict exit policy counts every recorded unknown/skip without changing defaults", () => {
  const opts = { ...sampleReport.options, strict: true };
  const summary = { pass: 1, info: 0, warn: 0, fail: 0, unknown: 0, skip: 0 };
  assert.equal(clampToExitCode("clean", "fail", opts, summary), 0);
  for (const status of ["unknown", "skip"]) {
    const gap = { ...summary, [status]: 1 };
    assert.equal(clampToExitCode("clean", "fail", opts, gap), 6);
    assert.equal(clampToExitCode("clean", "fail", { ...opts, strict: false }, gap), 0);
    assert.equal(clampToExitCode("failures", "fail", opts, gap), 2);
    assert.equal(clampToExitCode("warnings", "warn", opts, gap), 2);
    assert.equal(clampToExitCode("warnings", "fail", opts, gap), 1);
  }
  assert.equal(clampToExitCode("clean", "fail", opts), 6, "missing coverage must fail closed in strict mode");
  assert.equal(clampToExitCode("clean", "never", opts, summary), 3);
});
