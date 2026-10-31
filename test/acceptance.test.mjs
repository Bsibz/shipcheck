// Acceptance regressions from the independent review (P0 1–4, P1 5–8, P2).
// Every test builds its own fixtures in a private temp dir. Fake host tools
// are tiny shell scripts injected through the proc.ts test seam (not reachable
// from the CLI); nothing here executes artifact code, signs, or uses the network.

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, linkSync, symlinkSync, chmodSync, renameSync, appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "dist", "cli.js");
const require = createRequire(import.meta.url);
const dist = (name) => require(join(ROOT, "dist", name));

const { validateOutputs, writeReport } = dist("output.js");
const { runTool, setToolOverride, missingTools, usedToolPaths } = dist("proc.js");
const { Collector, defaultOptions } = dist("report.js");
const { readAppStructure } = dist("bundle.js");
const { runIdentity, runSignatures } = dist("checks-identity.js");
const { runAsarChecks } = dist("checks-asarx.js");
const { runNotarization } = dist("checks-notary.js");
const { spctlAssess } = dist("gatekeeper.js");
const { verifyHeaderHash, readHeader } = dist("asar.js");
const { pinZip, planZip, crc32 } = dist("zipsafe.js");
const { resolveTarget } = dist("input.js");
const { parseDisplay } = dist("codesign.js");

function sandbox() {
  return mkdtempSync(join(tmpdir(), "sc-acc-"));
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function cli(args, env) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000, env: env ?? process.env });
  assert.ok(r.error === undefined, `CLI failed to launch: ${r.error}`);
  return r;
}

const INFO_PLIST = (extra = "", exe = "demo-bin") => `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.test.demo</string>
  <key>CFBundleName</key><string>Demo</string>
  <key>CFBundleExecutable</key><string>${exe}</string>
  <key>CFBundleShortVersionString</key><string>1.2.3</string>
  <key>CFBundleVersion</key><string>45</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>${extra}
</dict></plist>`;

function makeApp(dir, name = "Demo.app", { plist = INFO_PLIST(), exe = "demo-bin" } = {}) {
  const bundle = join(dir, name);
  mkdirSync(join(bundle, "Contents", "MacOS"), { recursive: true });
  mkdirSync(join(bundle, "Contents", "Resources"), { recursive: true });
  writeFileSync(join(bundle, "Contents", "Info.plist"), plist);
  const p = join(bundle, "Contents", "MacOS", exe);
  writeFileSync(p, "#!/bin/sh\nexit 0\n");
  chmodSync(p, 0o755);
  return bundle;
}

function makeCtx(app, opts = {}, timeoutMs = 30_000) {
  return {
    app,
    target: { kind: "bundle", input: app.bundlePath },
    opts: { ...defaultOptions, ...opts },
    params: { timeoutMs },
    collector: new Collector(),
    toolMissing: new Set(),
    issues: [],
  };
}

function script(dir, name, body) {
  const p = join(dir, name);
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
  return p;
}

const sq = (s) => `'${s.replace(/'/g, "'\\''")}'`;

/** A fake `codesign` that answers the three call shapes shipcheck uses. */
function fakeCodesign(dir, { authority = [], team = "ABCDE12345", reqExit = 0, reqSilent = false, verifyExit = 0, name = "codesign" } = {}) {
  const display = [
    "Identifier=com.test.demo",
    "Format=app bundle with Mach-O thin (arm64)",
    "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+3 location=embedded",
    ...authority.map((a) => `Authority=${a}`),
    "Timestamp=Oct 1, 2026 at 12:00:00",
    `TeamIdentifier=${team}`,
  ];
  return script(
    dir,
    name,
    `case "$*" in
  *-R=*) ${reqExit !== 0 && !reqSilent ? "echo 'test-requirement: code failed to satisfy specified code requirement(s)' >&2" : ":"}; exit ${reqExit};;
  *--verify*) exit ${verifyExit};;
  *--entitlements*) exit 0;;
  *"-d --verbose=4"*) printf '%s\\n' ${display.map(sq).join(" ")} >&2; exit 0;;
esac
exit 0`,
  );
}

function withTool(tool, spec, fn) {
  setToolOverride(tool, spec);
  try {
    return fn();
  } finally {
    setToolOverride(tool, undefined);
  }
}

// ---- P0 1: output paths -------------------------------------------------------

test("P0-1 case-variant path into the audited bundle is refused (validate and CLI)", (t) => {
  const dir = sandbox();
  try {
    const app = makeApp(dir, "MyApp.app");
    if (!existsSync(join(dir, "myapp.app"))) return t.skip("case-sensitive volume: case variants are distinct paths");
    const plist = join(app, "Contents", "Info.plist");
    const before = readFileSync(plist);
    const variant = join(dir, "myapp.app", "contents", "info.plist");

    assert.match(validateOutputs(app, [{ flag: "--json", path: variant }]) ?? "", /inside the audited|overwrite/);
    assert.match(validateOutputs(app, [{ flag: "--json", path: variant }], true) ?? "", /inside the audited|overwrite/, "--force never unlocks the artifact");

    const r = cli([app, "--json", variant]);
    assert.equal(r.status, 5, r.stderr);
    assert.match(r.stderr, /refusing output/);
    assert.deepEqual(readFileSync(plist), before, "Info.plist untouched");

    // The artifact given in lower case, destination in true case.
    assert.ok(validateOutputs(join(dir, "myapp.app"), [{ flag: "--out", path: plist }], true) !== undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P0-1 hard links to bundle files are never overwritten, even with --force", () => {
  const dir = sandbox();
  try {
    const app = makeApp(dir);
    const alias = join(dir, "alias.json");
    linkSync(join(app, "Contents", "Info.plist"), alias);
    assert.match(validateOutputs(app, [{ flag: "--json", path: alias }], true) ?? "", /hard-linked/);
    const r = cli([app, "--json", alias, "--force"]);
    assert.equal(r.status, 5, r.stderr);
    assert.match(readFileSync(join(app, "Contents", "Info.plist"), "utf8"), /CFBundleIdentifier/);

    // writeReport re-verifies through the descriptor, not just the earlier path check.
    assert.throws(() => writeReport(alias, "owned", true));
    assert.match(readFileSync(alias, "utf8"), /CFBundleIdentifier/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P0-1 existing outputs need --force; creation is O_EXCL and never follows a symlink", () => {
  const dir = sandbox();
  try {
    const app = makeApp(dir);
    const out = join(dir, "report.json");
    writeFileSync(out, "precious");

    assert.match(validateOutputs(app, [{ flag: "--json", path: out }]) ?? "", /already exists.*--force/);
    const refused = cli([app, "--json", out]);
    assert.equal(refused.status, 5);
    assert.equal(readFileSync(out, "utf8"), "precious", "existing file untouched without --force");
    assert.throws(() => writeReport(out, "x"), /EEXIST/);

    assert.equal(validateOutputs(app, [{ flag: "--json", path: out }], true), undefined);
    const forced = cli([app, "--json", out, "--force"]);
    assert.notEqual(forced.status, 5, forced.stderr);
    assert.equal(JSON.parse(readFileSync(out, "utf8")).tool, "shipcheck");

    // A dangling symlink must not be created through.
    const victim = join(dir, "victim.txt");
    const dangling = join(dir, "dangling.json");
    symlinkSync(victim, dangling);
    assert.throws(() => writeReport(dangling, "x"));
    assert.equal(existsSync(victim), false, "symlink target was not created");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- P0 2: PATH cannot impersonate host tools -----------------------------------

test("P0-2 a fake codesign earlier on PATH is never run; absolute paths are recorded", () => {
  const dir = sandbox();
  try {
    const app = makeApp(dir);
    const bin = join(dir, "bin");
    mkdirSync(bin);
    const marker = join(dir, "fake-ran");
    for (const t of ["codesign", "spctl", "xattr", "lipo", "otool", "file", "plutil", "xcrun"]) {
      script(bin, t, `echo ran >> ${sq(marker)}\nprintf 'Authority=Developer ID Application: Evil (ABCDE12345)\\nAuthority=Apple Root CA\\n' >&2\nexit 0`);
    }
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, DEVELOPER_DIR: bin, DYLD_LIBRARY_PATH: bin };
    const r = cli([app, "--format", "json", "--fail-on", "never"], env);
    assert.equal(existsSync(marker), false, "no PATH-shadowed tool was executed");
    const report = JSON.parse(r.stdout);
    const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    assert.equal(byId["sign.presence"]?.status, "fail", "the real codesign said: not signed");
    assert.notEqual(byId["sign.author"]?.status, "pass");
    assert.equal(report.provenance.hostTools.codesign, "/usr/bin/codesign");
    assert.match(report.provenance.toolEnvironment, /DEVELOPER_DIR/);
    for (const p of Object.values(report.provenance.hostTools)) assert.ok(p.startsWith("/usr/"), p);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- P0 3: timeout / missing / overflow are unknown, not "broken" ---------------

test("P0-3 timeout, overflow and missing tools map to non-ok statuses", () => {
  const dir = sandbox();
  try {
    const slow = script(dir, "slow", "sleep 5");
    const t = withTool("codesign", { path: slow }, () => runTool("codesign", ["x"], { timeoutMs: 150 }));
    assert.equal(t.status, "timeout");
    assert.equal(t.timedOut, true);

    const noisy = script(dir, "noisy", "head -c 200000 /dev/zero | tr '\\0' a");
    const o = withTool("codesign", { path: noisy }, () => runTool("codesign", ["x"], { timeoutMs: 20_000 }, 1));
    assert.equal(o.status, "error");
    assert.equal(o.errorCode, "ENOBUFS");

    const m = withTool("codesign", { path: join(dir, "does-not-exist") }, () => runTool("codesign", ["x"], { timeoutMs: 1000 }));
    assert.equal(m.status, "missing");

    const okRun = runTool("file", ["-b", process.execPath], { timeoutMs: 20_000 });
    assert.equal(okRun.status, "ok");
    assert.equal(usedToolPaths().file, "/usr/bin/file");
    assert.throws(() => runTool("bash", ["-c", "true"], { timeoutMs: 1000 }), /not an allowed host tool/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P0-3 a timed-out or missing codesign yields unknown, never 'the signature is broken'", () => {
  const dir = sandbox();
  try {
    const app = readAppStructure(makeApp(dir));
    const slow = script(dir, "slow-codesign", "sleep 5");
    for (const [label, path, timeoutMs] of [["timeout", slow, 200], ["missing", join(dir, "gone"), 5000]]) {
      const ctx = makeCtx(app, {}, timeoutMs);
      withTool("codesign", { path }, () => runSignatures(ctx));
      for (const id of ["sign.presence", "sign.validity", "sign.nested", "sign.author", "sign.team", "sign.timestamp"]) {
        const f = ctx.collector.byId(id);
        assert.equal(f?.status, "unknown", `${label}: ${id} → ${f?.status}`);
        assert.equal(f.basis, "unknown");
      }
      assert.doesNotMatch(JSON.stringify(ctx.collector.findings), /signature is broken/);

      const n = makeCtx(app, {}, timeoutMs);
      withTool("codesign", { path }, () => runNotarization(n));
      assert.equal(n.collector.byId("not.stapled")?.status, "unknown");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P0-3 missing host tools are detected up front (exit-4 precondition)", () => {
  assert.deepEqual(missingTools(["codesign", "xattr", "lipo", "otool", "file", "plutil"]), []);
  const missing = withTool("lipo", { path: "/nonexistent/lipo" }, () => missingTools(["codesign", "lipo"]));
  assert.equal(missing.length, 1);
  assert.match(missing[0], /lipo/);
});

// ---- P0 4: signer trust ----------------------------------------------------------

function signerFindings(dir, codesignOpts) {
  const app = readAppStructure(makeApp(dir));
  const ctx = makeCtx(app);
  const cs = fakeCodesign(dir, codesignOpts);
  withTool("codesign", { path: cs }, () => runSignatures(ctx));
  return ctx;
}

test("P0-4 Apple Development and App Store signers warn (inferred), team is not 'verified'", () => {
  for (const [lead, expect] of [
    ["Apple Development: dev@example.com (ZZZZZZZZZZ)", /Apple Development|local development/i],
    ["Apple Distribution: Acme (ABCDE12345)", /App Store|Mac App Store/],
  ]) {
    const dir = sandbox();
    try {
      const ctx = signerFindings(dir, { authority: [lead, "Apple Worldwide Developer Relations Certification Authority", "Apple Root CA"] });
      const a = ctx.collector.byId("sign.author");
      assert.equal(a.status, "warn");
      assert.equal(a.basis, "inferred");
      assert.match(a.detail, expect);
      const team = ctx.collector.byId("sign.team");
      assert.equal(team.status, "warn");
      assert.notEqual(team.basis, "verified");
      // Integrity still passes: it is a different question.
      assert.equal(ctx.collector.byId("sign.validity").status, "pass");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("P0-4 self-signed 'Developer ID' name fails (no Apple chain, or requirement unsatisfied)", () => {
  let dir = sandbox();
  try {
    // Name claims Developer ID, chain stops at the certificate itself.
    const ctx = signerFindings(dir, { authority: ["Developer ID Application: Evil Corp (ABCDE12345)"] });
    assert.equal(ctx.collector.byId("sign.author").status, "fail");
    assert.equal(ctx.collector.byId("sign.team").status, "warn");
    assert.equal(ctx.collector.byId("sign.validity").status, "pass", "integrity alone is not trust");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  dir = sandbox();
  try {
    // Forged chain names, but codesign's own Developer ID requirement says no.
    const ctx = signerFindings(dir, {
      authority: ["Developer ID Application: Evil Corp (ABCDE12345)", "Developer ID Certification Authority", "Apple Root CA"],
      reqExit: 3,
    });
    const a = ctx.collector.byId("sign.author");
    assert.equal(a.status, "fail");
    assert.equal(a.basis, "verified");
    assert.match(a.detail, /NOT satisfied/);
    assert.notEqual(ctx.collector.byId("sign.team").status, "pass");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  dir = sandbox();
  try {
    const ctx = signerFindings(dir, { authority: ["Self Signed Thing"] });
    assert.equal(ctx.collector.byId("sign.author").status, "fail");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P0-4 only a codesign-verified Developer ID chain passes author and team", () => {
  const dir = sandbox();
  try {
    const ctx = signerFindings(dir, {
      authority: ["Developer ID Application: Acme (ABCDE12345)", "Developer ID Certification Authority", "Apple Root CA"],
      reqExit: 0,
    });
    const a = ctx.collector.byId("sign.author");
    assert.equal(a.status, "pass");
    assert.equal(a.basis, "verified");
    assert.equal(ctx.collector.byId("sign.team").status, "pass");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P0-4 a requirement check that fails for other reasons is unknown, not a trust verdict", () => {
  const dir = sandbox();
  try {
    const ctx = signerFindings(dir, {
      authority: ["Developer ID Application: Acme (ABCDE12345)", "Developer ID Certification Authority", "Apple Root CA"],
      reqExit: 1,
      reqSilent: true,
    });
    assert.equal(ctx.collector.byId("sign.author").status, "unknown");
    assert.notEqual(ctx.collector.byId("sign.team").status, "pass");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P0-4 team is never inferred from the certificate display name", () => {
  const text = ["Identifier=com.x", "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+3 location=embedded", "Authority=Developer ID Application: Acme (ABCDE12345)", "TeamIdentifier=not set"].join("\n");
  assert.equal(parseDisplay(text, "", 0).teamIdentifier, "not set");
});

// ---- P1 5: binary Info.plist -----------------------------------------------------

test("P1-5 a binary Info.plist is converted read-only and does not trip launch-blocker fails", () => {
  const dir = sandbox();
  try {
    const app = makeApp(dir);
    const plist = join(app, "Contents", "Info.plist");
    const xml = readFileSync(plist);
    const conv = spawnSync("/usr/bin/plutil", ["-convert", "binary1", plist], { encoding: "utf8" });
    assert.equal(conv.status, 0, conv.stderr);
    const bin = readFileSync(plist);
    assert.equal(bin.subarray(0, 6).toString("latin1"), "bplist");

    const s = readAppStructure(app);
    assert.equal(s.infoPlist.ok, true, s.infoPlist.error);
    assert.equal(s.execName, "demo-bin");
    assert.ok(s.execPath !== undefined);
    assert.deepEqual(readFileSync(plist), bin, "Info.plist bytes unchanged by the audit");

    const ctx = makeCtx(s);
    runIdentity(ctx);
    assert.equal(ctx.collector.byId("bundle.info-plist"), undefined);
    assert.equal(ctx.collector.byId("bundle.identifier").status, "info");
    assert.equal(ctx.collector.byId("bundle.version-fields").status, "pass");
    assert.equal(ctx.collector.byId("bundle.executable-present").status, "info");
    void xml;

    // A failing/hung plutil is unknown, not a launch blocker.
    const s2 = withTool("plutil", { path: join(dir, "no-plutil") }, () => readAppStructure(app));
    assert.equal(s2.infoPlist.ok, false);
    const c2 = makeCtx(s2);
    runIdentity(c2);
    assert.equal(c2.collector.byId("bundle.info-plist").status, "unknown");
    assert.equal(c2.collector.byId("bundle.identifier"), undefined);

    // plutil exiting non-zero means the file really is corrupt: that stays a fail.
    const refuses = script(dir, "refusing-plutil", "exit 1");
    const s3 = withTool("plutil", { path: refuses }, () => readAppStructure(app));
    const c3 = makeCtx(s3);
    runIdentity(c3);
    assert.equal(c3.collector.byId("bundle.info-plist").status, "fail");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- P1 6: ZIP bytes pinned -------------------------------------------------------

function buildStoredZip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name);
    const data = Buffer.from(e.data);
    const crc = e.crc ?? crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    const local = Buffer.concat([lh, name, data]);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE((3 << 8) | 20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE((0o100644 << 16) >>> 0, 38);
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

test("P1-6 a ZIP replaced or rewritten mid-audit is detected; the hash is of the pinned bytes", () => {
  const dir = sandbox();
  try {
    const zip = join(dir, "release.zip");
    const original = buildStoredZip([{ name: "a.txt", data: "original" }]);
    writeFileSync(zip, original);

    // Untouched → stable.
    let pin = pinZip(zip);
    assert.equal(pin.sha256, sha256(original));
    assert.equal(pin.changed(), false);
    pin.close();

    // Replaced by another file (new inode) after the hash was taken.
    pin = pinZip(zip);
    const swapped = join(dir, "swap.zip");
    writeFileSync(swapped, buildStoredZip([{ name: "a.txt", data: "SWAPPED!" }]));
    renameSync(swapped, zip);
    assert.equal(pin.changed(), true, "inode swap detected");
    assert.equal(pin.sha256, sha256(original), "hash still describes the bytes that were pinned");
    pin.close();

    // Rewritten in place (same inode, new size/mtime).
    pin = pinZip(zip);
    appendFileSync(zip, "trailing junk");
    assert.equal(pin.changed(), true, "in-place rewrite detected");
    pin.close();

    // Through the real resolver: the pin comes back to the caller.
    writeFileSync(zip, original);
    const resolved = resolveTarget(zip, { timeoutMs: 1000 });
    assert.ok(resolved.zipPin, "resolver returns the pinned descriptor");
    assert.equal(resolved.zipPin.sha256, sha256(original));
    assert.equal(resolved.zipPin.changed(), false);
    writeFileSync(zip, buildStoredZip([{ name: "a.txt", data: "different" }]));
    assert.equal(resolved.zipPin.changed(), true);
    resolved.zipPin.close();
    resolved.tempTree?.dispose();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P1-6 CRC-32 is enforced: corrupted stored data is not extracted or audited", () => {
  const dir = sandbox();
  try {
    const zip = join(dir, "corrupt.zip");
    writeFileSync(zip, buildStoredZip([{ name: "Demo.app/Contents/Info.plist", data: INFO_PLIST(), crc: 0xdeadbeef }]));
    assert.equal(planZip(zip).violations.length, 0, "structure is fine; only the data lies");
    const resolved = resolveTarget(zip, { timeoutMs: 1000 });
    assert.ok(resolved.issues.some((i) => i.id === "zip-extract-failed" && /CRC-32/.test(i.detail)), JSON.stringify(resolved.issues));
    resolved.zipPin?.close();
    resolved.tempTree?.dispose();

    const r = cli([zip, "--format", "json"]);
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stdout, /CRC-32/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P1-6 a normal ZIP audit records the pinned SHA-256 in provenance", () => {
  const dir = sandbox();
  try {
    const stage = join(dir, "stage");
    mkdirSync(stage);
    makeApp(stage);
    const zip = join(dir, "release.zip");
    const mk = spawnSync("ditto", ["-c", "-k", "--norsrc", stage, zip], { encoding: "utf8" });
    assert.equal(mk.status, 0, mk.stderr);
    const r = cli([zip, "--format", "json", "--fail-on", "never"]);
    const report = JSON.parse(r.stdout);
    assert.equal(report.provenance.artifact.sha256, sha256(readFileSync(zip)));
    assert.equal(report.provenance.artifact.sha256Basis, "file-stream");
    assert.equal(report.findings.find((f) => f.id === "provenance.artifact-changed"), undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- P1 7: ASAR integrity attribution ---------------------------------------------

function buildAsar(files, { jsonLen } = {}) {
  const root = { files: {} };
  const chunks = [];
  let offset = 0;
  for (const f of files) {
    const buf = Buffer.from(f.content);
    root.files[f.rel] = { size: buf.length, offset: String(offset), integrity: { algorithm: "SHA256", hash: sha256(buf) } };
    chunks.push(buf);
    offset += buf.length;
  }
  const json = Buffer.from(JSON.stringify(root));
  const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
  };
  const headerSize = 8 + json.length;
  return { bytes: Buffer.concat([u32(4), u32(headerSize), u32(headerSize - 4), u32(jsonLen ?? json.length), json, ...chunks]), json };
}

function integrityPlist(entries) {
  const body = Object.entries(entries)
    .map(([k, v]) => `<key>${k}</key><dict><key>algorithm</key><string>${v.algorithm ?? "SHA256"}</string><key>hash</key><string>${v.hash}</string></dict>`)
    .join("");
  return INFO_PLIST(`<key>ElectronAsarIntegrity</key><dict>${body}</dict>`);
}

test("P1-7 integrity results are labelled by the archive they belong to (no cross-attribution)", () => {
  const dir = sandbox();
  try {
    const good = buildAsar([{ rel: "a.js", content: "one" }]);
    const bad = buildAsar([{ rel: "b.js", content: "two" }]);
    const app = makeApp(dir, "Two.app", {
      plist: integrityPlist({
        "Resources/app.asar": { hash: sha256(good.json) },
        "Resources/other.asar": { hash: "0".repeat(64) },
        "Resources/gone.asar": { hash: "1".repeat(64) },
        "Resources/sha512.asar": { algorithm: "SHA512", hash: "2".repeat(128) },
      }),
    });
    const res = join(app, "Contents", "Resources");
    writeFileSync(join(res, "app.asar"), good.bytes);
    writeFileSync(join(res, "other.asar"), bad.bytes);
    writeFileSync(join(res, "sha512.asar"), good.bytes);

    const ctx = makeCtx(readAppStructure(app));
    runAsarChecks(ctx);
    const integ = ctx.collector.findings.filter((f) => f.id.startsWith("asar.integrity:"));
    const ids = integ.map((f) => f.id).sort();
    assert.deepEqual(ids, [
      "asar.integrity:Contents/Resources/app.asar",
      "asar.integrity:Contents/Resources/other.asar",
      "asar.integrity:Contents/Resources/sha512.asar",
    ]);
    assert.equal(new Set(ids).size, ids.length, "exactly one result per archive");
    const by = Object.fromEntries(integ.map((f) => [f.id, f]));
    assert.equal(by["asar.integrity:Contents/Resources/app.asar"].status, "pass");
    assert.match(by["asar.integrity:Contents/Resources/app.asar"].detail, /EnableEmbeddedAsarIntegrityValidation/);
    assert.match(by["asar.integrity:Contents/Resources/app.asar"].detail, /unverified/);
    assert.equal(by["asar.integrity:Contents/Resources/other.asar"].status, "fail");
    assert.equal(by["asar.integrity:Contents/Resources/sha512.asar"].status, "unknown", "non-SHA256 algorithm is not 'tampering'");
    const stale = ctx.collector.findings.filter((f) => f.id.startsWith("asar.integrity-declared"));
    assert.equal(stale.length, 1, "stale key warned about once, not once per asar");
    assert.match(stale[0].detail, /gone\.asar/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P1-7 implausible header sizes are unknown/rejected, never allocated or called tampering", () => {
  const dir = sandbox();
  try {
    const huge = buildAsar([{ rel: "a.js", content: "x" }], { jsonLen: 0xfffffff0 });
    const p = join(dir, "huge.asar");
    writeFileSync(p, huge.bytes);
    assert.equal(verifyHeaderHash(p, "0".repeat(64)).status, "invalid");
    assert.equal(readHeader(p), undefined);

    const app = makeApp(dir, "Huge.app", { plist: integrityPlist({ "Resources/huge.asar": { hash: "0".repeat(64) } }) });
    writeFileSync(join(app, "Contents", "Resources", "huge.asar"), huge.bytes);
    const ctx = makeCtx(readAppStructure(app));
    runAsarChecks(ctx);
    assert.equal(ctx.collector.byId("asar.integrity:Contents/Resources/huge.asar").status, "unknown");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- P1 8: Gatekeeper evidence ----------------------------------------------------

test("P1-8 spctl: override= is not a pass; source/origin evidence survives line order", () => {
  const dir = sandbox();
  try {
    const target = join(dir, "X.app");
    const good = script(dir, "spctl-good", `printf '%s\\n' '${target}: accepted' 'source=Notarized Developer ID' 'origin=Developer ID Application: Acme (ABCDE12345)'`);
    const ok = withTool("spctl", { path: good }, () => spctlAssess(target, { timeoutMs: 5000 }));
    assert.equal(ok.assessment, "accepted");
    assert.equal(ok.source, "Notarized Developer ID");
    assert.equal(ok.origin, "Developer ID Application: Acme (ABCDE12345)");

    const off = script(dir, "spctl-off", `printf '%s\\n' '${target}: accepted' 'source=Notarized Developer ID' 'override=security disabled' 'origin=Developer ID Application: Acme (ABCDE12345)'`);
    const o = withTool("spctl", { path: off }, () => spctlAssess(target, { timeoutMs: 5000 }));
    assert.equal(o.assessment, "unknown");
    assert.equal(o.override, "security disabled");

    const slow = script(dir, "spctl-slow", "sleep 5");
    const s = withTool("spctl", { path: slow }, () => spctlAssess(target, { timeoutMs: 150 }));
    assert.equal(s.assessment, "unknown");
    assert.match(s.note, /timed out/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- P2 --------------------------------------------------------------------------

test("P2 stapled wording does not claim validity; notarization reads the bundle-level facts", () => {
  const dir = sandbox();
  try {
    const app = readAppStructure(makeApp(dir));
    const cs = script(
      dir,
      "codesign-stapled",
      `case "$*" in
  *"-d --verbose=4"*) printf '%s\\n' 'Identifier=com.test.demo' 'Notarization Ticket=stapled' >&2; exit 0;;
esac
exit 0`,
    );
    const ctx = makeCtx(app);
    withTool("codesign", { path: cs }, () => runNotarization(ctx));
    const f = ctx.collector.byId("not.stapled");
    assert.equal(f.status, "pass");
    assert.match(f.detail, /unverified without --stapler/);
    assert.doesNotMatch(f.detail, /works offline/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("P2 CFBundleExecutable traversal and a symlinked executable never leave the bundle", () => {
  const dir = sandbox();
  try {
    const outside = join(dir, "outside-secret");
    writeFileSync(outside, "/Users/someone/secret/path\n");
    const trav = readAppStructure(makeApp(dir, "Trav.app", { plist: INFO_PLIST("", "../../../outside-secret") }));
    assert.equal(trav.execPath, undefined);
    assert.ok(trav.escapes.some((e) => e.kind === "executable-name"));

    const linkApp = makeApp(dir, "Link.app");
    rmSync(join(linkApp, "Contents", "MacOS", "demo-bin"));
    symlinkSync(outside, join(linkApp, "Contents", "MacOS", "demo-bin"));
    const link = readAppStructure(linkApp);
    assert.equal(link.execPath, undefined);
    assert.ok(link.escapes.some((e) => e.kind === "executable" || e.kind === "symlink"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
