// End-to-end tests: spawn the real CLI (dist/cli.js) against fixtures built
// fresh in a temp dir. No signing required — an unsigned skeleton bundle is
// itself a deterministic defect (gatekeeper + signature fails → exit 2).
//
// These tests only exercise shipcheck (auditor) + its own temp extraction;
// they never sign or notarize anything.

import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "dist", "cli.js");
const PKG_VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;

function run(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000 });
  assert.ok(r.error === undefined, `CLI failed to launch: ${r.error}`);
  assert.equal(r.signal, null, `CLI was killed by signal ${r.signal}`);
  return r;
}

function makeSkeletonApp(dir, name = "Demo.app") {
  const bundle = join(dir, name);
  mkdirSync(join(bundle, "Contents", "MacOS"), { recursive: true });
  mkdirSync(join(bundle, "Contents", "Resources"), { recursive: true });
  writeFileSync(
    join(bundle, "Contents", "Info.plist"),
    `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.test.demo</string>
  <key>CFBundleName</key><string>Demo</string>
  <key>CFBundleExecutable</key><string>demo-bin</string>
  <key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>`,
  );
  const exe = join(bundle, "Contents", "MacOS", "demo-bin");
  writeFileSync(exe, "#!/bin/sh\nexit 0;\n");
  chmodSync(exe, 0o755);
  return bundle;
}

function makeZip(dir, name, populateStage) {
  const stage = join(dir, "stage");
  mkdirSync(stage, { recursive: true });
  populateStage(stage);
  const zip = join(dir, name);
  const mk = spawnSync("ditto", ["-c", "-k", "--norsrc", stage, zip], { encoding: "utf8" });
  assert.equal(mk.status, 0, `fixture zip creation failed: ${mk.stderr}`);
  return zip;
}

test("usage errors: missing input path → exit 3 with stderr detail", () => {
  const r = run([join(tmpdir(), `definitely-not-real-${Date.now()}`)]);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /shipcheck:/);
  assert.match(r.stderr, /does not exist/);
});

test("usage errors: unknown flag → exit 3", () => {
  const r = run(["--definitely-not-a-flag"]);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /unknown flag/);
});

test("--help prints the usage contract, exit 0", () => {
  const r = run(["--help"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /EXIT CODES/);
  assert.match(r.stdout, /Read-only/);
});

test("--version prints the package version, exit 0", () => {
  const r = run(["--version"]);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), PKG_VERSION);
});

test("unsigned skeleton app → exit 2 with failure findings; --fail-on never → 0", () => {
  const dir = mkdtempSync(join(tmpdir(), "sc-int-"));
  try {
    const app = makeSkeletonApp(dir);
    const r = run([app, "--format", "json"]);
    if (r.status !== 2) assert.fail(`expected exit 2, got ${r.status}. stderr=${r.stderr || "(none)"}`);
    const report = JSON.parse(r.stdout);
    assert.equal(report.tool, "shipcheck");
    assert.equal(report.verdict, "failures");
    assert.ok(report.summary.fail >= 1, "at least one fail expected");
    const ids = report.findings.map((f) => f.id);
    assert.ok(ids.includes("gatekeeper.assess"), `gatekeeper.assess missing; ids=${ids.join()}`);
    assert.ok(ids.includes("sign.validity"), `sign.validity missing; ids=${ids.join()}`);

    const r2 = run([app, "--format", "json", "--fail-on", "never"]);
    assert.equal(r2.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("text + markdown formats render against the skeleton app", () => {
  const dir = mkdtempSync(join(tmpdir(), "sc-int-"));
  try {
    const app = makeSkeletonApp(dir);
    const txt = run([app]);
    assert.equal(txt.status, 2);
    assert.match(txt.stdout, /VERDICT/);
    const md = run([app, "--format", "markdown"]);
    assert.equal(md.status, 2);
    assert.ok(md.stdout.startsWith("# shipcheck report"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--out writes the report; unusable --out path → exit 5 with stdout preserved", () => {
  const dir = mkdtempSync(join(tmpdir(), "sc-int-"));
  try {
    const app = makeSkeletonApp(dir);
    const outPath = join(dir, "report.json");
    const r = run([app, "--format", "json", "--out", outPath]);
    assert.equal(r.status, 2);
    assert.match(r.stdout, /\[report written to/);
    const saved = JSON.parse(readFileSync(outPath, "utf8"));
    assert.equal(saved.tool, "shipcheck");

    const bad = run([app, "--format", "json", "--out", dir]); // target is a directory
    assert.equal(bad.status, 5);
    assert.match(bad.stderr, /could not write --out/);
    assert.match(bad.stdout, /"tool"/, "report body still printed to stdout");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release ZIP containing an app audits end-to-end via temp extraction", () => {
  const dir = mkdtempSync(join(tmpdir(), "sc-int-"));
  try {
    const zip = makeZip(dir, "release.zip", (stage) => makeSkeletonApp(stage));
    const r = run([zip, "--format", "json"]);
    const report = JSON.parse(r.stdout);
    assert.equal(r.status, 2);
    assert.ok(report.target.bundlePath !== undefined, "resolved an app inside the zip");
    assert.ok(report.findings.some((f) => f.status === "fail"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release ZIP without any .app → target.zip-no-app fail → exit 2 (0 with --fail-on never)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sc-int-"));
  try {
    const zip = makeZip(dir, "plain.zip", (stage) => writeFileSync(join(stage, "notes.txt"), "not an app\n"));
    const r = run([zip, "--format", "json"]);
    const report = JSON.parse(r.stdout);
    assert.equal(r.status, 2);
    const ids = report.findings.map((f) => f.id);
    assert.ok(ids.includes("target.zip-no-app"), `zip-no-app missing; ids=${ids.join()}`);

    const r2 = run([zip, "--fail-on", "never"]);
    assert.equal(r2.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("strict CLI rejects contradictory collection policy in either argument order", () => {
  for (const args of [["--strict", "--fail-on", "never"], ["--fail-on", "never", "--strict"]]) {
    const r = run(["unused.dmg", ...args]);
    assert.equal(r.status, 3);
    assert.match(r.stderr, /--strict cannot be combined/);
  }
  assert.match(run(["--help"]).stdout, /--strict/);
});

test("strict real CLI rejects unresolved DMG coverage while preserving report truth", () => {
  const dir = mkdtempSync(join(tmpdir(), "shipcheck-strict-"));
  try {
    const dmg = join(dir, "unreadable.dmg");
    writeFileSync(dmg, "not a disk image");
    const normal = run([dmg, "--format", "json"]);
    const strict = run([dmg, "--format", "json", "--strict"]);
    assert.equal(normal.status, 0);
    assert.equal(strict.status, 6);
    const a = JSON.parse(normal.stdout), b = JSON.parse(strict.stdout);
    assert.equal(a.verdict, "clean");
    assert.equal(b.verdict, a.verdict);
    assert.deepEqual(b.summary, a.summary);
    assert.deepEqual(b.findings, a.findings);
    assert.ok(b.summary.unknown > 0);
    assert.equal(a.options.strict, false);
    assert.equal(b.options.strict, true);
    const text = run([dmg, "--strict"]);
    assert.equal(text.status, 6);
    assert.match(text.stdout, /VERDICT CLEAN\nUNRESOLVED/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
