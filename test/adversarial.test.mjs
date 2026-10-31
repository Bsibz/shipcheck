// Adversarial tests for the surfaces a release auditor must not lie about:
//   - HTML report injection (artifact strings, finding metadata, provenance)
//   - evidence classification (VERIFIED / INFERRED / UNKNOWN) fallbacks
//   - malformed / tampered ASAR archives (never a crash, never a silent pass)
//   - a healthy ASAR parser fixture (the positive control)
//   - hostile report-output paths (artifact overwrite, bundle interior, links)
//
// Everything is hand-built in a private temp dir: no network, no reliance on
// installed apps, and every hostile byte is explicit here.

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, linkSync, symlinkSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import assert from "node:assert/strict";

import { readHeader, verifyHeaderHash, verifyAsarPerFile, scanHeaderForBuildPaths } from "../dist/asar.js";
import { escapeHtml, evidenceClass, renderHtml } from "../dist/render/html.js";
import { validateOutputs, writeReport } from "../dist/output.js";
import { sanitizeDeep, defaultOptions } from "../dist/report.js";

// ---- helpers ---------------------------------------------------------------

function sandbox() {
  return mkdtempSync(join(tmpdir(), "sc-adv-"));
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
};

/**
 * files: [{ rel, content, integrity? }] — content is laid out in array order.
 * opts can lie about the prologue (magic / headerSize / payloadSize) or replace
 * the index text, which is exactly how a corrupt or hostile asar looks.
 */
function buildAsar(files, opts = {}) {
  const root = { files: {} };
  const chunks = [];
  let offset = 0;
  for (const f of files) {
    const buf = Buffer.from(f.content ?? "", "utf8");
    const parts = f.rel.split("/");
    let dir = root.files;
    for (const p of parts.slice(0, -1)) {
      if (dir[p] === undefined) dir[p] = { files: {} };
      dir = dir[p].files;
    }
    const entry = { size: f.size ?? buf.length, offset: f.offset ?? String(offset) };
    if (f.integrity !== false) entry.integrity = { algorithm: "SHA256", hash: sha256(buf) };
    dir[parts[parts.length - 1]] = entry;
    chunks.push(buf);
    offset += buf.length;
  }
  const jsonBuf = Buffer.from(opts.jsonText ?? JSON.stringify(root), "utf8");
  const headerSize = opts.headerSize ?? 8 + jsonBuf.length;
  const prologue = Buffer.concat([
    u32(opts.magic ?? 4),
    u32(headerSize),
    u32(opts.payloadSize ?? headerSize - 4),
    u32(opts.jsonLen ?? jsonBuf.length),
  ]);
  return Buffer.concat([prologue, jsonBuf, ...chunks]);
}

function writeAsar(dir, bytes, name = "app.asar") {
  const p = join(dir, name);
  writeFileSync(p, bytes);
  return p;
}

function makeReport(overrides = {}) {
  return {
    tool: "shipcheck",
    version: "0.1.0",
    reportVersion: 1,
    timestamp: "2026-10-29T00:00:00.000Z",
    runtime: { macos: "Darwin 27.2.0 (test)", arch: "arm64", node: "v24" },
    target: { kind: "bundle", input: "/tmp/Demo.app", bundlePath: "/tmp/Demo.app", bundleName: "Demo.app" },
    provenance: {
      artifact: { path: "/tmp/Demo.app", kind: "bundle", sha256Basis: "not-applicable-directory" },
      network: "offline",
      networkNote: "no network calls were made",
      extraction: "none",
      generatedBy: "shipcheck 0.1.0",
    },
    options: { ...defaultOptions },
    notes: [],
    findings: [
      { id: "bundle.identifier", group: "bundle identity", status: "pass", basis: "verified", detail: "CFBundleIdentifier: com.demo" },
    ],
    summary: { pass: 1, warn: 0, fail: 0, info: 0, unknown: 0, skip: 0 },
    basisSummary: { verified: 1, inferred: 0, unknown: 0 },
    verdict: "clean",
    ...overrides,
  };
}

// ---- HTML injection --------------------------------------------------------

test("escapeHtml neutralizes markup, attribute-break and entity payloads", () => {
  const cases = [
    ["<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"],
    ['"><img src=x onerror=alert(1)>', "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"],
    ["' onmouseover='alert(1)", "&#39; onmouseover=&#39;alert(1)"],
    ["&amp; &lt;", "&amp;amp; &amp;lt;"],
    ["javascript:alert(1)", "javascript:alert(1)"],
  ];
  for (const [input, want] of cases) assert.equal(escapeHtml(input), want);
  // The five HTML metacharacters can never survive escaping.
  assert.doesNotMatch(escapeHtml(`<>&"'`), /[<>"']/);
  // Non-strings are coerced, not trusted as markup.
  assert.equal(escapeHtml(42), "42");
  assert.equal(escapeHtml(undefined), "undefined");
});

test("renderHtml keeps hostile artifact text inert end to end", () => {
  const evil = `</title><script>alert("x")</script>`;
  const findingId = `identity";<img src=x onerror=alert(1)>`;
  const report = makeReport({
    target: { kind: "bundle", input: evil, bundlePath: evil, bundleName: evil },
    notes: [`<svg onload=alert(1)>`],
    findings: [
      {
        id: findingId,
        group: `<style>body{display:none}</style>`,
        status: "fail",
        basis: "verified",
        detail: `</pre><script>alert("detail")</script>`,
        evidence: [`</details><iframe src="javascript:alert(1)">`],
        hint: `"><a href="javascript:alert(1)">fix</a>`,
      },
    ],
    summary: { pass: 0, warn: 0, fail: 1, info: 0, unknown: 0, skip: 0 },
    verdict: "failures",
    provenance: {
      artifact: { path: `"><iframe src=//evil>`, kind: "bundle", sha256Basis: "unavailable" },
      network: "offline",
      networkNote: `</dd><script>alert("prov")</script>`,
      extraction: "none",
      generatedBy: `shipcheck 0.1.0"><svg onload=alert(1)>`,
    },
  });
  const out = renderHtml(report);

  // No executable element an artifact could have supplied survived.
  for (const tag of ["script", "iframe", "img", "svg", "object", "embed"]) {
    assert.doesNotMatch(out.toLowerCase(), new RegExp(`<${tag}`), `${tag} must not be injected`);
  }
  // The renderer's own single <style> block is the only one.
  assert.equal((out.match(/<style>/g) ?? []).length, 1);
  assert.equal((out.match(/<\/style>/g) ?? []).length, 1);
  // Escaped forms are present, so we know the text was rendered, not dropped.
  assert.match(out, /&lt;script&gt;alert\(&quot;x&quot;\)&lt;\/script&gt;/);
  assert.match(out, /&lt;img src=x onerror=alert\(1\)&gt;/);
  // Finding anchors use the slug, so an id cannot break out of the attribute.
  assert.match(out, /id="f-identity-img-src-x-onerror-alert-1"/);
  // The report stays self-contained and non-loading.
  assert.match(out, /Content-Security-Policy" content="default-src 'none'/);
  assert.match(out, /<meta name="referrer" content="no-referrer">/);
});

test("artifact control characters and bidi overrides never reach rendered HTML", () => {
  const dirty = makeReport({
    target: {
      kind: "bundle",
      input: "/tmp/\u001b[31mRed\u202eDemo.app",
      bundlePath: "/tmp/Demo.app",
      bundleName: "Red\u202eDemo.app",
    },
    findings: [
      {
        id: "bundle.identifier",
        group: "bundle identity",
        status: "pass",
        basis: "verified",
        detail: "id: com.\u001b[0mdead\u202ebeef",
        evidence: ["plist\u0007line"],
      },
    ],
  });
  const sanitized = sanitizeDeep(dirty);
  const out = renderHtml(sanitized);
  // eslint-disable-next-line no-control-regex
  assert.doesNotMatch(out, /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/);
  assert.match(out, /Red\uFFFD+Demo\.app/);
});

// ---- evidence basis --------------------------------------------------------

test("evidenceClass claims VERIFIED only when a finding is actually grounded", () => {
  // Explicit basis always wins.
  assert.equal(evidenceClass({ id: "x", group: "g", status: "pass", basis: "inferred", detail: "", evidence: ["raw"] }), "inferred");
  // Unknown / skip are never upgraded to verified by having evidence lines.
  assert.equal(evidenceClass({ id: "x", group: "g", status: "unknown", detail: "", evidence: ["raw"] }), "unknown");
  assert.equal(evidenceClass({ id: "x", group: "g", status: "skip", detail: "", evidence: ["raw"] }), "unknown");
  // Legacy reports without basis: raw evidence => verified, bare claim => inferred.
  assert.equal(evidenceClass({ id: "x", group: "g", status: "pass", detail: "", evidence: ["raw"] }), "verified");
  assert.equal(evidenceClass({ id: "x", group: "g", status: "pass", detail: "" }), "inferred");
  assert.equal(evidenceClass({ id: "x", group: "g", status: "warn", detail: "", evidence: [] }), "inferred");

  // The rendered legend counts the same classification it displays.
  const out = renderHtml(
    makeReport({
      findings: [
        { id: "a", group: "g", status: "pass", detail: "grounded", evidence: ["raw"] },
        { id: "b", group: "g", status: "warn", detail: "claimed" },
        { id: "c", group: "g", status: "unknown", detail: "undetermined" },
      ],
      summary: { pass: 1, warn: 1, fail: 0, info: 0, unknown: 1, skip: 0 },
      verdict: "warnings",
    }),
  );
  assert.match(out, /directly observed in tool or filesystem output · 1/);
  assert.match(out, /concluded indirectly, not directly observed · 1/);
  assert.match(out, /undetermined or skipped · 1/);
});

// ---- malformed ASAR --------------------------------------------------------

test("asar prologue corruption yields no header instead of a guessed one", () => {
  const dir = sandbox();
  try {
    const healthy = buildAsar([{ rel: "app/main.js", content: "console.log(1)\n" }]);
    const cases = {
      "truncated to 8 bytes": { bytes: healthy.subarray(0, 8), header: "invalid" },
      "truncated prologue (12 bytes)": { bytes: healthy.subarray(0, 12), header: "invalid" },
      // The marker/size fields are not trusted ahead of the hash, so a file
      // whose prologue lies still hashes a slice — it can only ever mismatch.
      "wrong pickle marker": { bytes: buildAsar([{ rel: "a.js", content: "x" }], { magic: 3 }), header: "mismatch" },
      // headerSize and payloadSize must agree (payload == headerSize - 4).
      "pickles disagree": { bytes: buildAsar([{ rel: "a.js", content: "x" }], { payloadSize: 8 + 64 }), header: "mismatch" },
      "jsonLen larger than the file": { bytes: buildAsar([{ rel: "a.js", content: "x" }], { jsonLen: 4096 }), header: "invalid" },
      "empty file": { bytes: Buffer.alloc(0), header: "invalid" },
    };
    for (const [name, c] of Object.entries(cases)) {
      const p = writeAsar(dir, c.bytes, `${name.replace(/\W+/g, "-")}.asar`);
      assert.equal(readHeader(p), undefined, `${name} must not produce a header`);
      // Never a match on a corrupt prologue, and never a throw.
      assert.notEqual(verifyHeaderHash(p, "ab".repeat(32)).status, "match", name);
      assert.equal(verifyHeaderHash(p, "ab".repeat(32)).status, c.header, name);
      const perFile = verifyAsarPerFile(p, 10);
      assert.deepEqual(
        { attempted: perFile.attempted, verified: perFile.verifiedFiles, bad: perFile.mismatchedFiles.length },
        { attempted: 0, verified: 0, bad: 0 },
        `${name} must not claim per-file evidence`,
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("malformed ASAR index and tampered payload never become a pass", () => {
  const dir = sandbox();
  try {
    // 1. Index JSON that is not JSON at all but has honest lengths.
    const badJson = writeAsar(dir, buildAsar([{ rel: "a.js", content: "x" }], { jsonText: '{"files": {"a.js": ' }), "bad-json.asar");
    const h1 = readHeader(badJson);
    assert.ok(h1, "structure parsed, contents did not");
    assert.equal(h1.files, 0);
    assert.equal(h1.jsonTruncated, false);
    // No `json` means no downstream consumer can trust the index text.
    assert.equal(h1.json, undefined);
    assert.equal(verifyAsarPerFile(badJson, 10).attempted, 0);

    // 2. `files` of the wrong type: parsed, but nothing to enumerate.
    const wrongShape = writeAsar(dir, buildAsar([{ rel: "a.js", content: "x" }], { jsonText: '{"files": "not-a-dir"}' }), "wrong-shape.asar");
    const h2 = readHeader(wrongShape);
    assert.ok(h2);
    assert.equal(h2.files, 0);
    assert.deepEqual(h2.sampleFiles, []);
    assert.equal(verifyAsarPerFile(wrongShape, 10).attempted, 0);

    // 3. Payload edited after packaging: every embedded hash must fail.
    const tampered = buildAsar([
      { rel: "app/main.js", content: "console.log(1)\n" },
      { rel: "app/package.json", content: '{"main":"main.js"}\n' },
    ]);
    const flipped = Buffer.from(tampered);
    flipped[flipped.length - 3] ^= 0xff; // mutate one byte inside the content region
    const tamperedPath = writeAsar(dir, flipped, "tampered.asar");
    const checked = verifyAsarPerFile(tamperedPath, 10);
    assert.equal(checked.attempted, 2);
    assert.equal(checked.verifiedFiles, 1, "only the untouched entry verifies");
    assert.equal(checked.mismatchedFiles.length, 1);
    assert.equal(checked.mismatchedFiles[0].rel, "app/package.json");
    assert.match(checked.mismatchedFiles[0].recorded, /^[0-9a-f]{64}$/);

    // 4. Hostile index entries (offset past EOF, negative size) are reported,
    //    never thrown, and never counted as verified.
    const hostileIndex = buildAsar([
      { rel: "past-eof.js", content: "abc", offset: "4096" },
      { rel: "negative.js", content: "abc", size: -1 },
    ]);
    const hostilePath = writeAsar(dir, hostileIndex, "hostile-index.asar");
    const hostile = verifyAsarPerFile(hostilePath, 10);
    assert.equal(hostile.verifiedFiles, 0);
    // Out-of-range entries cannot be hashed: reported as unreadable (unknown), never as a pass and never as "tampering".
    assert.equal(hostile.mismatchedFiles.length, 0);
    assert.deepEqual(hostile.unreadable.map((m) => m.rel).sort(), ["negative.js", "past-eof.js"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- healthy ASAR positive control ----------------------------------------

test("healthy ASAR fixture parses, hashes and caps deterministically", () => {
  const dir = sandbox();
  try {
    const main = Buffer.from("console.log('ship')\n", "utf8");
    const pkg = Buffer.from('{"name":"demo","version":"1.0.0","main":"main.js"}\n', "utf8");
    const dep = Buffer.from("module.exports = 1;\n", "utf8");
    const bytes = buildAsar([
      { rel: "app/main.js", content: main },
      { rel: "app/package.json", content: pkg },
      { rel: "app/node_modules/dep/index.js", content: dep },
    ]);
    const p = writeAsar(dir, bytes);

    const header = readHeader(p);
    assert.ok(header);
    assert.equal(header.files, 3);
    assert.equal(header.fileEntries, 3);
    assert.equal(header.jsonTruncated, false);
    assert.deepEqual(header.sampleFiles, ["app/main.js", "app/package.json", "app/node_modules/dep/index.js"]);
    assert.equal(header.headerSize, 8 + header.jsonLen);
    assert.match(header.json, /"integrity"/, "real asars carry per-file records");

    // The recorded hash is over the proven slice [16, 16 + jsonLen).
    const recorded = sha256(bytes.subarray(16, 16 + header.jsonLen));
    assert.equal(verifyHeaderHash(p, recorded).status, "match");
    assert.equal(verifyHeaderHash(p, recorded.toUpperCase()).status, "match", "case-insensitive compare");
    const wrong = verifyHeaderHash(p, "cd".repeat(32));
    assert.equal(wrong.status, "mismatch");
    assert.equal(wrong.computed, recorded);

    const perFile = verifyAsarPerFile(p, 10);
    assert.deepEqual(
      { attempted: perFile.attempted, verified: perFile.verifiedFiles, bad: perFile.mismatchedFiles.length, cap: perFile.capReached },
      { attempted: 3, verified: 3, bad: 0, cap: false },
    );

    // Caps degrade to "not checked", never to a fabricated pass.
    const capped = readHeader(p, 8);
    assert.ok(capped);
    assert.equal(capped.jsonTruncated, true);
    assert.equal(capped.files, 0);
    assert.equal(capped.json, undefined);
    const perFileCap = verifyAsarPerFile(p, 1);
    assert.equal(perFileCap.attempted, 1);
    assert.equal(perFileCap.verifiedFiles, 1);
    assert.equal(perFileCap.capReached, true);

    // Host build paths are visible in the index and are surfaced as evidence.
    const leaky = writeAsar(
      dir,
      buildAsar([{ rel: "app/main.js", content: "x" }], {
        jsonText: JSON.stringify({ files: { "app/main.js": { size: 1, offset: "0", source: "/Users/someone/secret/project/src/main.ts" } } }),
      }),
      "leaky.asar",
    );
    assert.deepEqual(scanHeaderForBuildPaths(leaky), ["/Users/someone/secret/project/src/main.ts"]);
    assert.deepEqual(scanHeaderForBuildPaths(p), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- hostile output paths -------------------------------------------------

test("report destinations cannot overwrite the artifact, its bundle, or each other", () => {
  const dir = sandbox();
  try {
    const zip = join(dir, "release.zip");
    const bytes = Buffer.from("PK\u0003\u0004 pretend release bytes", "binary");
    writeFileSync(zip, bytes);

    // Same path as the artifact.
    assert.match(validateOutputs(zip, [{ flag: "--out", path: zip }]) ?? "", /would overwrite|inside the audited artifact/);
    // Relative spelling of the same file.
    assert.ok(validateOutputs(zip, [{ flag: "--json", path: join(dir, ".", "release.zip") }]) !== undefined);
    // Symlink pointing at the artifact.
    const sym = join(dir, "report.json");
    symlinkSync(zip, sym);
    assert.match(validateOutputs(zip, [{ flag: "--json", path: sym }]) ?? "", /overwrite|inside|same file/);
    // Hard link sharing the artifact's inode.
    const hard = join(dir, "hard.json");
    linkSync(zip, hard);
    assert.match(validateOutputs(zip, [{ flag: "--json", path: hard }]) ?? "", /same file as the audited artifact/);
    // Two flags aimed at one destination.
    const same = join(dir, "same.json");
    assert.match(validateOutputs(zip, [{ flag: "--json", path: same }, { flag: "--out", path: same }]) ?? "", /point at the same file/);

    // A directory artifact may not have outputs written inside it, or onto it.
    const app = join(dir, "Demo.app");
    mkdirSync(join(app, "Contents", "Resources"), { recursive: true });
    writeFileSync(join(app, "Contents", "Info.plist"), "<plist/>");
    assert.match(validateOutputs(app, [{ flag: "--out", path: join(app, "Contents", "report.txt") }]) ?? "", /inside the audited/);
    assert.match(validateOutputs(app, [{ flag: "--out", path: app }]) ?? "", /overwrite|inside the audited/);
    assert.match(validateOutputs(join(app, "Contents"), [{ flag: "--out", path: join(app, "Contents", "r.txt") }]) ?? "", /inside the audited/);

    // A safe sibling destination is allowed and actually written.
    const safe = join(dir, "report.txt");
    assert.equal(validateOutputs(zip, [{ flag: "--out", path: safe }]), undefined);
    writeReport(safe, "shipcheck report\n");
    assert.equal(readFileSync(safe, "utf8"), "shipcheck report\n");
    assert.deepEqual(readFileSync(zip), bytes, "artifact bytes untouched");
    assert.equal(existsSync(join(app, "Contents", "report.txt")), false, "no bundle-interior write happened");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
