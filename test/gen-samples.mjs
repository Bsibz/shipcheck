// Regenerate samples/sample-report.{txt,json,md} honestly: build a demo
// fixture bundle fresh in a temp dir, then run the REAL dist/cli.js against
// it with each format. Findings in the samples are genuine CLI output.
//
// Fixture is deliberately unsigned, non-notarized and Gatekeeper-rejected,
// so the sample demonstrates fail/warn/skip classes end to end. Exit codes
// here are never asserted — generation is not a gate.
//
// The only cosmetic edits to the captured output: the throwaway fixture tmp
// path is mapped to a stable demo path, and the host runtime header line is
// normalized. Nothing about findings, statuses, or evidence is edited.

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir, cpus, type as osType, release as osRelease } from "node:os";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "dist", "cli.js");
const SAMPLES = join(ROOT, "samples");
const DEMO_PATH = "/Users/demo/Downloads/Demo.app";
const DEMO_RUNTIME = "Darwin 27 (demo documentation run) · arm64 · node v24";

function makeDemoApp(dir) {
  const bundle = join(dir, "Demo.app");
  mkdirSync(join(bundle, "Contents", "MacOS"), { recursive: true });
  mkdirSync(join(bundle, "Contents", "Resources"), { recursive: true });
  writeFileSync(
    join(bundle, "Contents", "Info.plist"),
    `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.demo</string>
  <key>CFBundleName</key><string>Demo</string>
  <key>CFBundleExecutable</key><string>Demo</string>
  <key>CFBundleShortVersionString</key><string>1.0.0</string>
  <key>NSHumanReadableCopyright</key><string>Sample fixture for shipcheck docs.</string>
</dict></plist>`,
  );
  // shell-script executable: codesign reports "not signed at all", lipo and
  // file cannot classify it → deterministic fail + unknown mix
  const exe = join(bundle, "Contents", "MacOS", "Demo");
  writeFileSync(exe, "#!/bin/sh\nexit 0;\n");
  chmodSync(exe, 0o755);
  return bundle;
}

const app = makeDemoApp(mkdtempSync(join(tmpdir(), "sc-samples-")));
mkdirSync(SAMPLES, { recursive: true });

const runs = [
  { fmt: "text", file: "sample-report.txt" },
  { fmt: "json", file: "sample-report.json" },
  { fmt: "markdown", file: "sample-report.md" },
  { fmt: "html", file: "sample-report.html" },
];

const codes = [];
for (const { fmt, file } of runs) {
  const r = spawnSync(process.execPath, [CLI, app, "--format", fmt], { encoding: "utf8", timeout: 120_000 });
  if (r.error !== undefined) {
    console.error(`generation failed for ${file}: ${r.error}`);
    process.exit(1);
  }
  let body = r.stdout;
  if (fmt === "json") {
    const report = JSON.parse(body);
    report.runtime = { macos: "Darwin 27 (demo documentation run)", arch: "arm64", node: "v24" };
    body = JSON.stringify(report, null, 2) + "\n";
  } else {
    body = body.replace(/^macOS .*$/m, `macOS ${DEMO_RUNTIME}`);
  }
  const cpu = cpus()[0]?.model;
  const hostLabel = `${osType()} ${osRelease()} (${cpu ?? "unknown-CPU"})`;
  body = body.replaceAll(app, DEMO_PATH).replaceAll(dirname(app), "/private/tmp/shipcheck-demo").replaceAll(hostLabel, "Darwin (sanitized demo host)");
  if (cpu !== undefined) body = body.replaceAll(cpu, "sanitized demo host");
  writeFileSync(join(SAMPLES, file), body);
  codes.push(`${file}: exit ${r.status}`);
}

console.log(`${codes.join("\n")}\n\nsamples refreshed in ${SAMPLES} (fixture temp tree removed)`);
rmSync(dirname(app), { recursive: true, force: true });
