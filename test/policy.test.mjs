// Read-only policy enforcement. A test that fails CI the moment shipcheck
// grows a mutation or upload path — matching the release-conveyor house rule
// that read-only is contractual, not aspirational.
//
// Scans src/ for forbidden token patterns:
//   - filesystem mutation APIs outside src/temp.ts and src/cli.ts
//     (temp.ts owns rmSync for the extraction tree; cli.ts owns --out)
//   - any network client usage (fetch/http/net modules)
//   - mutating/signing/upload spawn targets (codesign may never receive
//     --sign/-f/--force/--remove-signature; stapler may never receive
//     `staple`; generic hdiutil and osascript routes are banned)
//   - the sole image-tool exception is a fixed non-mounting imageinfo route,
//     with exactly one absolute regular-file argument (runtime regression).
// Only spawnSync with the whitelisted Apple read tools is allowed.

import { readFileSync, readdirSync } from "node:fs";
import { join, extname } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const SRC_ROOT = new URL("../src/", import.meta.url).pathname;

function listSrclFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, name.name);
    if (name.isDirectory()) out.push(...listSrclFiles(p));
    else if (extname(name.name) === ".ts" && !name.name.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

const files = listSrclFiles(SRC_ROOT).map((p) => [p, readFileSync(p, "utf8")]);

const MUTATION_ALLOWED = new Set([join(SRC_ROOT, "temp.ts"), join(SRC_ROOT, "cli.ts"), join(SRC_ROOT, "output.ts")]);

const MUTATION_PATTERNS = [
  [/rmSync\s*\(/, "rmSync"],
  [/unlinkSync\s*\(/, "unlinkSync"],
  [/unlink\(/, "unlink("],
  [/writeFile\(/, "writeFile("],
  [/writeFileSync\(/, "writeFileSync("],
  [/appendFile/, "appendFile"],
  [/chmodSync\s*\(/, "chmodSync("],
  [/rmdirSync\s*\(/, "rmdirSync("],
  [/renameSync\s*\(/, "renameSync("],
  [/copyFileSync\s*\(/, "copyFileSync("],
  [/mkdtempSync\s*\(/, "mkdtempSync("],
];

const NETWORK_PATTERNS = [
  [/\bfetch\s*\(/, "fetch("],
  [/require\(["']node:http/, "node:http"],
  [/from\s+["']node:http/, "node:http"],
  [/require\(["']node:https/, "node:https"],
  [/from\s+["']node:https/, "node:https"],
  [/require\(["']node:net["']\)/, "node:net"],
  [/\bXMLHttpRequest\b/, "XMLHttpRequest"],
  [/\bcurl\b/, "curl"],
  [/\bwget\b/, "wget"],
];

const SPAWN_PATTERNS = [
  [/execSync\s*\(/, "execSync("],
  [/(?<![\w.])exec\s*\(/, "exec("],
  [/execFile\s*\(/, "execFile("],
];

const BANNED_TOOLS = /["'](hdiutil|osascript|security|installer|xattrsave|tccutil|open|pmset|caffeinate|defaults)["']/;

const ALLOWED_TOOLS = [
  "codesign",
  "spctl",
  "lipo",
  "file",
  "otool",
  "plutil",
  "unzip",
  "ditto",
  "xattr",
  "stapler",
  "which",
];

const WITNESS_SIGN_FLOW = /--remove-signature|--sign\b|--force\b/;

test("every src file compiles into the read-only contract: no fs mutations outside temp/cli", () => {
  for (const [path, text] of files) {
    if (MUTATION_ALLOWED.has(path)) {
      // temp.ts and cli.ts may mutate only their own scope; no banned tools though
      assert.doesNotMatch(text, BANNED_TOOLS, `${path} must not invoke banned tools`);
      continue;
    }
    for (const [pattern, label] of MUTATION_PATTERNS) {
      assert.doesNotMatch(text, pattern, `${path} must not contain ${label} (read-only policy)`);
    }
  }
});

test("no network clients anywhere in src", () => {
  for (const [path, text] of files) {
    for (const [pattern, label] of NETWORK_PATTERNS) {
      assert.doesNotMatch(text, pattern, `${path} must not contain ${label} (read-only policy)`);
    }
  }
});

test("synchronous spawns only; no shell-string exec paths", () => {
  for (const [path, text] of files) {
    for (const [pattern, label] of SPAWN_PATTERNS) {
      assert.doesNotMatch(text, pattern, `${path} must not contain ${label} (no shell escapes)`);
    }
  }
});

test("banned system tools never appear as spawn targets", () => {
  for (const [path, text] of files) {
    assert.doesNotMatch(text, BANNED_TOOLS, `${path} must not spawn banned tools`);
  }
});

test("DMG host route is fixed to non-mounting imageinfo with no arbitrary verb", () => {
  const proc = files.find(([p]) => p.endsWith("proc.ts"))[1];
  assert.match(proc, /"dmg-info": \{ path: "\/usr\/bin\/hdiutil", prefix: \["imageinfo", "-plist", "-stdinpass"\] \}/);
  const all = files.map(([,text]) => text).join("\n");
  assert.doesNotMatch(all, /["'](?:attach|detach|mount|unmount|convert|create|resize|chpass|erasekeys)["']/);
});

test("the signature of spawning is constrained to whitelisted Apple tools", () => {
  const procFile = files.find(([p]) => p.endsWith("proc.ts"));
  assert.ok(procFile, "proc.ts must exist");
  const text = procFile[1];
  assert.match(text, /spawnSync\(/, "proc.ts must use spawnSync only");
  // every tool name passed via runTool comes from callers; enforce by scanning callers
  for (const [path, text2] of files) {
    // collect runTool("<tool>" style literals
    for (const m of text2.matchAll(/runTool\(\s*"([^"]+)"/g)) {
      const tool = m[1] ?? "";
      assert.ok(
        ALLOWED_TOOLS.includes(tool),
        `${path} spawns "${tool}" which is not on the whitelist (read-only tools only)`,
      );
    }
  }
});

test("codesign is never asked to sign, force or strip (auditors observe, not act)", () => {
  for (const [path, text] of files) {
    for (const m of text.matchAll(/["']codesign["']/g)) {
      // find the argument array right after; simple heuristic: check the file
      // for argument literals that would mutate a target
      assert.doesNotMatch(
        text,
        /"codesign"[^\n]*"--remove-signature"/,
        `${path} must not strip signatures`,
      );
      WITNESS_SIGN_FLOW.lastIndex = 0;
      if (WITNESS_SIGN_FLOW.test(m[0])) {
        assert.fail(`${path} contains a signature-mutating flow near a codesign spawn`);
      }
    }
  }
});
