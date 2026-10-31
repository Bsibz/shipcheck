// Suspicious absolute/local build path scanning.
//
// Targets three surfaces, all read-only:
//   1. Info.plist string values (parsed plist — no encoding surprises)
//   2. asar header JSON (see asar.ts)
//   3. Mach-O binaries, streamed byte scan for /Users/…, /home/…, /tmp/…,
//      /root/…, /private/var/folders/…
//
// False positives are possible (docs, comments); findings show hit counts and
// bounded samples, and never print file contents beyond the matched strings.

import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import type { PlistDict, PlistValue } from "./plist.js";

const BUILD_PATH_RE = /\/(?:Users|home|root|tmp|private\/var\/folders|private\/tmp)\/[A-Za-z0-9_.\-/@]+/g;

export interface PathScan {
  surface: string;
  hits: string[];
  truncated: boolean;
  /** Binary scans only: false when the file could not be opened/read or exceeded the byte cap. */
  complete?: boolean;
}

export function scanPlistStrings(dict: PlistDict, surface = "Info.plist"): PathScan {
  const hits: string[] = [];
  let truncated = false;
  const visit = (v: PlistValue, depth: number): void => {
    if (depth > 8) return;
    if (typeof v === "string") {
      if (/^\/(Users|home|root|tmp)\//.test(v)) {
        if (hits.length < 8) hits.push(v.length > 200 ? v.slice(0, 200) + "…" : v);
        else truncated = true;
      }
    } else if (Array.isArray(v)) {
      for (const e of v) visit(e, depth + 1);
    } else if (typeof v === "object" && v !== null) {
      for (const value of Object.values(v)) visit(value, depth + 1);
    }
  };
  for (const value of Object.values(dict)) {
    if (value === undefined) continue;
    visit(value, 0);
  }
  return { surface, hits, truncated };
}

const CHUNK = 4 * 1024 * 1024;
const OVERLAP = 4096;

/** Streamed byte scan for host build paths inside a Mach-O (or any binary). */
export function scanBinaryForBuildPaths(path: string, maxHits = 8, maxBytes = 256 * 1024 * 1024): PathScan {
  const surface = "binary:" + path;
  const seen = new Set<string>();
  const hits: string[] = [];
  let truncated = false;
  let complete = true;
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return { surface, hits, truncated, complete: false };
  }
  try {
    const size = fstatSync(fd).size;
    const limit = Math.min(size, maxBytes);
    if (size > maxBytes) complete = false;
    let tail = "";
    let pos = 0;
    while (pos < limit) {
      const len = Math.min(CHUNK, limit - pos);
      const buf = Buffer.alloc(len);
      const got = readSync(fd, buf, 0, len, pos);
      if (got <= 0) break;
      const text = tail + buf.toString("latin1", 0, got);
      for (const m of text.matchAll(BUILD_PATH_RE)) {
        const hit = m[0].length > 160 ? m[0].slice(0, 160) + "…" : m[0];
        if (!seen.has(hit)) {
          seen.add(hit);
          if (hits.length < maxHits) hits.push(hit);
          else truncated = true;
        }
      }
      tail = text.slice(Math.max(0, text.length - OVERLAP));
      pos += got;
    }
  } catch {
    // read trouble is not fatal: report what we have, marked incomplete
    complete = false;
  } finally {
    closeSync(fd);
  }
  return { surface, hits, truncated, complete };
}
