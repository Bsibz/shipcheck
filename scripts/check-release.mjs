// Release readiness gate. Read-only: never publishes, tags, or pushes.
// Usage: node scripts/check-release.mjs [--tag vX.Y.Z]
// Also honours GITHUB_REF_NAME when GITHUB_REF_TYPE=tag.
//
// Verifies that package.json, package-lock.json, the built CLI's --version,
// CHANGELOG.md, an optional git tag, and the npm tarball contents agree, and
// that nothing private ships in the tarball.

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const problems = [];
const fail = (m) => problems.push(m);
const read = (p) => readFileSync(join(ROOT, p), "utf8");

const pkg = JSON.parse(read("package.json"));
const lock = JSON.parse(read("package-lock.json"));

if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(pkg.version)) fail(`package.json version ${pkg.version} is not semver`);
if (pkg.private === true) fail("package.json is private: npm publish would refuse");
if (pkg.license !== "MIT" || !existsSync(join(ROOT, "LICENSE"))) fail("license metadata/file mismatch");
if (lock.name !== pkg.name || lock.version !== pkg.version || lock.packages?.[""]?.version !== pkg.version) {
  fail(`package-lock.json (${lock.name}@${lock.version}) disagrees with package.json (${pkg.name}@${pkg.version})`);
}

const cli = spawnSync(process.execPath, [join(ROOT, "dist", "cli.js"), "--version"], { encoding: "utf8" });
if (cli.status !== 0 || cli.stdout.trim() !== pkg.version) {
  fail(`dist/cli.js --version printed ${JSON.stringify(cli.stdout.trim())}, expected ${pkg.version} (run npm run build)`);
}

const changelog = read("CHANGELOG.md");
if (!new RegExp(`^## \\[${pkg.version.replaceAll(".", "\\.")}\\]`, "m").test(changelog)) {
  fail(`CHANGELOG.md has no "## [${pkg.version}]" heading`);
}

const tagArg = process.argv.includes("--tag") ? process.argv[process.argv.indexOf("--tag") + 1] : undefined;
const tag = tagArg ?? (process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : undefined);
if (tag !== undefined && tag !== `v${pkg.version}`) fail(`tag ${tag} does not match v${pkg.version}`);

const bin = read(pkg.bin.shipcheck);
if (!bin.startsWith("#!/usr/bin/env node")) fail("bin target lacks a node shebang");

// Tarball contents (dry run: nothing is written or uploaded).
const pack = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: ROOT, encoding: "utf8" });
if (pack.status !== 0) fail(`npm pack --dry-run failed: ${pack.stderr.trim()}`);
else {
  const files = JSON.parse(pack.stdout)[0].files.map((f) => f.path);
  for (const f of files) {
    if (/^(src|test|scripts|\.github|\.local-evidence)\//.test(f) || /\.(log|tgz)$/.test(f)) fail(`unexpected file in tarball: ${f}`);
  }
  for (const need of ["dist/cli.js", "LICENSE", "README.md", "CHANGELOG.md", "SECURITY.md", "package.json"]) {
    if (!files.includes(need)) fail(`tarball is missing ${need}`);
  }
  // Private-path hygiene: any /Users/<name>/ other than documented placeholders.
  const allowed = new Set(["demo", "owner", "someone", "dev", "example", "you", "name", "user"]);
  const leaks = new Set();
  for (const f of files) {
    const abs = join(ROOT, f);
    if (!existsSync(abs) || /\.(png|jpg|gif|ico)$/.test(f)) continue;
    const text = readFileSync(abs, "utf8");
    for (const m of text.matchAll(/\/Users\/([A-Za-z0-9._-]+)\//g)) if (!allowed.has(m[1])) leaks.add(`${f}: ${m[0]}`);
    if (/\/private\/var\/folders\/[0-9a-z_]{2}\//.test(text)) leaks.add(`${f}: /private/var/folders/...`);
  }
  for (const l of leaks) fail(`possible private machine path in tarball: ${l}`);
  console.log(`tarball: ${files.length} files`);
}

if (problems.length > 0) {
  console.error(`release check FAILED for ${pkg.name}@${pkg.version}:\n- ${problems.join("\n- ")}`);
  process.exit(1);
}
console.log(`release check ok: ${pkg.name}@${pkg.version} (package.json = lockfile = CLI --version = CHANGELOG${tag ? ` = tag ${tag}` : ""})`);
