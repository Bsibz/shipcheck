// Temp-tree lifecycle and confined ZIP extraction. Shipcheck's only
// filesystem writes are:
//   1. exactly one temp extraction tree per run (for zip inputs), and
//   2. report files the user explicitly asked for (see src/output.ts).
//
// The inspected artifact is never modified or deleted; the destination temp
// tree is created by os.tmpdir()-based mkdtemp (mode 0700) and removed at exit.

import { closeSync, mkdirSync, mkdtempSync, openSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { readEntryBytes, type ZipEntry, type ZipPlan } from "./zipsafe.js";

export interface TempTree {
  root: string;
  dispose(): void;
}

export function makeTempTree(prefix: string): TempTree {
  const root = mkdtempSync(join(tmpdir(), prefix));
  let disposed = false;
  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    process.removeListener("exit", dispose);
    try {
      rmSync(root, { recursive: true, force: true });
    } catch {
      // Best effort only; the OS cleans tmpdir eventually. Never fatal.
    }
  };
  // Cleanup on abnormal exit paths too.
  process.once("exit", dispose);
  return { root, dispose };
}

export interface ExtractResult {
  files: number;
  dirs: number;
  symlinks: number;
  bytes: number;
}

function confined(root: string, rel: string): string {
  const abs = resolve(root, rel);
  if (abs !== root && !abs.startsWith(root + sep)) throw new Error(`refusing path outside extraction root: ${rel}`);
  return abs;
}

/**
 * Extract a validated plan into an empty directory. Files are created with
 * exclusive-create (never overwrite, never follow), sized exactly, and byte
 * totals are enforced on actual output. Symlinks are created last.
 * Throws on any inconsistency; the caller disposes the tree.
 */
export function extractPlan(zip: string | number, plan: ZipPlan, root: string, maxTotalBytes: number, maxEntryBytes: number): ExtractResult {
  if (plan.violations.length > 0) throw new Error("refusing to extract a plan with violations");
  const res: ExtractResult = { files: 0, dirs: 0, symlinks: 0, bytes: 0 };
  const ownsFd = typeof zip === "string";
  const fd = typeof zip === "string" ? openSync(zip, "r") : zip;
  try {
    const links: ZipEntry[] = [];
    for (const e of plan.entries) {
      const abs = confined(root, e.path);
      if (e.kind === "dir") {
        mkdirSync(abs, { recursive: true, mode: 0o755 });
        res.dirs += 1;
      } else if (e.kind === "symlink") {
        links.push(e);
      } else {
        mkdirSync(dirname(abs), { recursive: true, mode: 0o755 });
        const data = readEntryBytes(fd, e, maxEntryBytes);
        res.bytes += data.length;
        if (res.bytes > maxTotalBytes) throw new Error("actual extracted bytes exceed the total limit");
        writeFileSync(abs, data, { flag: "wx", mode: (e.mode & 0o111) !== 0 ? 0o755 : 0o644 });
        res.files += 1;
      }
    }
    for (const e of links) {
      const abs = confined(root, e.path);
      mkdirSync(dirname(abs), { recursive: true, mode: 0o755 });
      symlinkSync(e.linkTarget as string, abs);
      res.symlinks += 1;
    }
  } finally {
    if (ownsFd) closeSync(fd);
  }
  return res;
}
