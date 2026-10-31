// Public-repo hygiene: tracked files must carry only sanitized/synthetic data.
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const files = execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8" })
  .split("\0")
  .filter((f) => f !== "" && existsSync(join(ROOT, f)));
const PLACEHOLDERS = new Set(["demo", "owner", "someone", "dev", "example", "you", "name", "user", "x"]);

test("tracked files contain no private home paths or private evidence directories", () => {
  const hits = [];
  for (const f of files) {
    if (f === "test/hygiene.test.mjs" || f === ".gitignore" || f === "scripts/check-release.mjs") continue;
    const text = readFileSync(join(ROOT, f), "utf8");
    for (const m of text.matchAll(/\/Users\/([A-Za-z0-9._-]+)\//g)) if (!PLACEHOLDERS.has(m[1])) hits.push(`${f}: ${m[0]}`);
    if (/\.local-evidence|\.night-build|\/private\/var\/folders\/[0-9a-z_]{2}\//.test(text)) hits.push(`${f}: private-looking path`);
  }
  assert.deepEqual(hits, []);
});

test("no receipts, tarballs, logs, or app bundles are tracked", () => {
  const bad = files.filter((f) => /\.(tgz|log|dmg|zip|asar)$/.test(f) || /\.app\//.test(f));
  assert.deepEqual(bad, []);
});
