// CI proof of --strict exit behaviour against the built CLI.
// Uses only synthetic, throwaway fixtures. Never inspects a real app.
//   default run on an unreadable DMG container -> exit 0 (clean, UNRESOLVED)
//   same run with --strict                      -> exit 6
//   --strict --fail-on never                    -> exit 3 (usage)
//   unsigned skeleton .app                      -> exit 2 default AND strict (failure outranks 6)

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "cli.js");
const run = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 120_000 });
const dir = mkdtempSync(join(tmpdir(), "shipcheck-ci-"));
let bad = 0;
const expect = (label, got, want) => {
  const ok = got === want;
  if (!ok) bad++;
  console.log(`${ok ? "ok  " : "FAIL"} ${label}: exit ${got} (expected ${want})`);
};

try {
  const dmg = join(dir, "unreadable.dmg");
  writeFileSync(dmg, "not a disk image");
  expect("default, unreadable dmg", run([dmg, "--format", "json"]).status, 0);
  expect("--strict, unreadable dmg", run([dmg, "--format", "json", "--strict"]).status, 6);
  expect("--strict --fail-on never", run([dmg, "--strict", "--fail-on", "never"]).status, 3);

  const app = join(dir, "Demo.app");
  mkdirSync(join(app, "Contents", "MacOS"), { recursive: true });
  writeFileSync(join(app, "Contents", "Info.plist"),
    `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.demo</string>
  <key>CFBundleName</key><string>Demo</string>
  <key>CFBundleExecutable</key><string>Demo</string>
  <key>CFBundleShortVersionString</key><string>1.0.0</string>
</dict></plist>`);
  const exe = join(app, "Contents", "MacOS", "Demo");
  writeFileSync(exe, "#!/bin/sh\nexit 0\n");
  chmodSync(exe, 0o755);
  expect("default, unsigned app", run([app, "--format", "json"]).status, 2);
  expect("--strict, unsigned app", run([app, "--format", "json", "--strict"]).status, 2);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
process.exit(bad === 0 ? 0 : 1);
