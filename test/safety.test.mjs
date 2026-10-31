// Hostile-input tests: ZIP traversal/symlink/bomb defenses, output-overwrite
// refusal, simultaneous receipts, evidence labels and provenance. ZIPs are
// built by hand so we can craft entries no archiver would produce.

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "dist", "cli.js");
const require = createRequire(import.meta.url);
const { planZip, checkEntryName, symlinkStaysInside, DEFAULT_ZIP_LIMITS } = require(join(ROOT, "dist", "zipsafe.js"));

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c = (crc ^ buf[i]) & 0xff;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** entries: {name, data?, mode?, deflate?, usizeLie?} */
function buildZip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name);
    const data = Buffer.from(e.data ?? "");
    const comp = e.deflate ? deflateRawSync(data) : data;
    const usize = e.usizeLie ?? data.length;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(e.deflate ? 8 : 0, 8);
    lh.writeUInt32LE(crc32(data), 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(usize, 22);
    lh.writeUInt16LE(name.length, 26);
    const local = Buffer.concat([lh, name, comp]);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE((3 << 8) | 20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(e.deflate ? 8 : 0, 10);
    ch.writeUInt32LE(crc32(data), 16);
    ch.writeUInt32LE(comp.length, 20);
    ch.writeUInt32LE(usize, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(((e.mode ?? 0o100644) << 16) >>> 0, 38);
    ch.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([ch, name]));
    locals.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

const SKELETON = [
  { name: "Demo.app/Contents/Info.plist", data: `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.t.d</string><key>CFBundleExecutable</key><string>d</string></dict></plist>` },
  { name: "Demo.app/Contents/MacOS/d", data: "#!/bin/sh\n", mode: 0o100755 },
];

function sandbox() {
  return mkdtempSync(join(tmpdir(), "sc-safe-"));
}
function cli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000 });
}
const ids = (plan) => plan.violations.map((v) => v.id);

test("entry names: traversal, absolute, backslash, NUL, control chars are rejected", () => {
  for (const bad of ["../evil", "a/../../evil", "/etc/passwd", "a\\b", "a\0b", "a\nb", "C:/x"]) {
    assert.ok("id" in checkEntryName(bad), `should reject ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(checkEntryName("./a//b/"), { path: "a/b" });
});

test("symlink confinement math", () => {
  assert.equal(symlinkStaysInside("A/Current", "B"), true);
  assert.equal(symlinkStaysInside("A/B/link", "../C"), true);
  assert.equal(symlinkStaysInside("A/link", "../../x"), false);
  assert.equal(symlinkStaysInside("A/link", "/etc"), false);
  assert.equal(symlinkStaysInside("link", ".."), false);
});

test("planZip flags traversal, symlink escapes, nested-under-symlink, collisions, specials", () => {
  const dir = sandbox();
  try {
    const z = join(dir, "bad.zip");
    writeFileSync(z, buildZip([
      { name: "../escape.txt", data: "x" },
      { name: "link", data: "/etc", mode: 0o120777 },
      { name: "link2", data: "../..", mode: 0o120777 },
      { name: "okdir/", mode: 0o040755 },
      { name: "okdir/inner", data: "i" },
      { name: "okdir/INNER", data: "dup" },
      { name: "dev", data: "", mode: 0o020644 },
      { name: "okdir/sl", data: "inner", mode: 0o120777 },
      { name: "okdir/sl/under", data: "w" },
    ]));
    const got = ids(planZip(z));
    for (const want of ["zip-path-traversal", "zip-symlink-escape", "zip-name-collision", "zip-special-file"]) {
      assert.ok(got.includes(want), `${want} missing from ${got.join()}`);
    }
    assert.ok(got.filter((i) => i === "zip-symlink-escape").length >= 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("planZip enforces entry-count, total-size and ratio limits; rejects truncated files", () => {
  const dir = sandbox();
  try {
    const z = join(dir, "many.zip");
    writeFileSync(z, buildZip([{ name: "a", data: "1" }, { name: "b", data: "2" }]));
    assert.ok(ids(planZip(z, { ...DEFAULT_ZIP_LIMITS, maxEntries: 1 })).includes("zip-entry-count"));
    assert.ok(ids(planZip(z, { ...DEFAULT_ZIP_LIMITS, maxEntryBytes: 0 })).includes("zip-entry-size"));
    assert.ok(ids(planZip(z, { ...DEFAULT_ZIP_LIMITS, maxTotalBytes: 1 })).includes("zip-total-size"));
    const bomb = join(dir, "bomb.zip");
    writeFileSync(bomb, buildZip([{ name: "z", data: Buffer.alloc(4 * 1024 * 1024), deflate: true }]));
    assert.ok(ids(planZip(bomb, { ...DEFAULT_ZIP_LIMITS, ratioFloorBytes: 1024, maxRatio: 100 })).includes("zip-ratio"));
    const trunc = join(dir, "trunc.zip");
    writeFileSync(trunc, readFileSync(z).subarray(0, 40));
    assert.ok(ids(planZip(trunc)).includes("zip-malformed"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI: hostile zip is rejected before extraction, nothing escapes, temp tree gone", () => {
  const dir = sandbox();
  try {
    const victim = join(dir, "escape.txt");
    const z = join(dir, "evil.zip");
    writeFileSync(z, buildZip([...SKELETON, { name: "../escape.txt", data: "pwn" }]));
    const before = readdirSync(tmpdir()).filter((n) => n.startsWith("shipcheck-zip-")).length;
    const r = cli([z, "--format", "json"]);
    const report = JSON.parse(r.stdout);
    assert.equal(r.status, 2);
    assert.ok(report.findings.some((f) => f.id === "target.zip-unsafe" && f.status === "fail"));
    assert.equal(report.target.bundlePath, undefined, "nothing audited");
    assert.equal(existsSync(victim), false);
    const after = readdirSync(tmpdir()).filter((n) => n.startsWith("shipcheck-zip-")).length;
    assert.ok(after <= before, "no leaked temp trees");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI: benign hand-built zip extracts with provenance sha256 and evidence labels", () => {
  const dir = sandbox();
  try {
    const z = join(dir, "ok.zip");
    writeFileSync(z, buildZip([...SKELETON, { name: "__MACOSX/._x", data: "meta" }]));
    const r = cli([z, "--format", "json"]);
    const report = JSON.parse(r.stdout);
    assert.ok(report.target.bundlePath !== undefined);
    assert.equal(report.target.zip.skippedMetadataEntries, 1);
    assert.match(report.provenance.artifact.sha256, /^[0-9a-f]{64}$/);
    assert.equal(report.provenance.network, "offline");
    assert.ok(report.findings.every((f) => ["verified", "inferred", "unknown"].includes(f.basis)));
    assert.ok(report.findings.filter((f) => f.status === "unknown").every((f) => f.basis === "unknown"));
    const gk = report.findings.find((f) => f.id === "gatekeeper.assess");
    if (gk) { assert.equal(gk.status, "unknown"); assert.equal(gk.basis, "unknown"); }
    assert.equal(report.basisSummary.verified + report.basisSummary.inferred + report.basisSummary.unknown, report.findings.length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI: outputs never overwrite the artifact (or sit inside it, or collide)", () => {
  const dir = sandbox();
  try {
    const z = join(dir, "r.zip");
    const bytes = buildZip(SKELETON);
    writeFileSync(z, bytes);
    for (const flag of ["--out", "--json", "--html"]) {
      const r = cli([z, flag, z]);
      assert.equal(r.status, 5, `${flag}: ${r.stderr}`);
      assert.deepEqual(readFileSync(z), bytes, "artifact untouched");
    }
    const link = join(dir, "link.json");
    spawnSync("ln", ["-s", z, link]);
    assert.equal(cli([z, "--json", link]).status, 5);
    const hard = join(dir, "hard.json");
    spawnSync("ln", [z, hard]);
    assert.equal(cli([z, "--json", hard]).status, 5);
    assert.deepEqual(readFileSync(z), bytes);
    assert.equal(cli([z, "--json", join(dir, "same"), "--out", join(dir, "same")]).status, 5);
    const app = join(dir, "App.app");
    mkdirSync(join(app, "Contents"), { recursive: true });
    writeFileSync(join(app, "Contents", "Info.plist"), "<plist/>");
    assert.equal(cli([app, "--out", join(app, "Contents", "report.txt")]).status, 5);
    assert.equal(existsSync(join(app, "Contents", "report.txt")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI: --json FILE alongside text stdout writes a valid receipt", () => {
  const dir = sandbox();
  try {
    const z = join(dir, "r.zip");
    writeFileSync(z, buildZip(SKELETON));
    const jf = join(dir, "r.json");
    const r = cli([z, "--json", jf]);
    assert.match(r.stdout, /VERDICT/);
    assert.match(r.stdout, /EVIDENCE verified=/);
    const rec = JSON.parse(readFileSync(jf, "utf8"));
    assert.equal(rec.tool, "shipcheck");
    assert.ok(rec.provenance.artifact.sha256);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("artifact-controlled control characters are neutralized in reports", () => {
  const dir = sandbox();
  try {
    const z = join(dir, "r.zip");
    const plist = SKELETON[0].data.replace("com.t.d", "com.t.\u001b[31mred\u202e");
    writeFileSync(z, buildZip([{ ...SKELETON[0], data: plist }, SKELETON[1]]));
    const out = cli([z, "--format", "json"]).stdout;
    assert.doesNotMatch(out, /\u202e/);
    assert.doesNotMatch(cli([z]).stdout, /\u001b/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
