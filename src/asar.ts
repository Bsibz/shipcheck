// ASAR archive inspection: header parse, integrity verification against the
// ElectronAsarIntegrity record in Info.plist, and per-file verification.
//
// All structure facts here were verified against real release apps on macOS 27
// (ChatGPT.app 640MB asar, Grok Bot.app). Locked facts:
//   file[0..4)   = u32 marker 4
//   file[4..8)   = headerSize
//   file[8..12)  = header pickle payload size (= headerSize - 4)
//   file[12..16) = jsonLen (note: u32 length prefix of the JSON string)
//   file[16 .. 16+jsonLen) = file index JSON  ← this slice's SHA256 matches the
//     Info.plist ElectronAsarIntegrity hash (confirmed twice live)
//   content region base = headerSize + 8  ← verified: the offset-0 entry reads
//     clean text exactly at that base
//   Backing-store offsets in the JSON may be strings; parse with parseInt.
//   Per-file integrity blocks are OPTIONAL — fine, real asars ship without
//   them (ChatGPT's does). Never treat absence as failure.

import { createHash } from "node:crypto";
import { closeSync, existsSync, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { join, relative } from "node:path";
import { containedRealPath } from "./bundle.js";

export interface AsarEntry {
  rel: string;
  offset: number;
  size: number;
  integrity?: { algorithm?: string; hash?: string; blockSize?: number; blocks?: string[] };
}

export interface AsarHeader {
  jsonLen: number;
  headerSize: number;
  files: number;
  fileEntries: number;
  sampleFiles: string[];
  json?: string;
  jsonTruncated: boolean;
}

export function readHeader(asarPath: string, maxJsonBytes = 16 * 1024 * 1024): AsarHeader | undefined {
  const fd = openSync(asarPath, "r");
  try {
    const head = Buffer.alloc(16);
    if (readSync(fd, head, 0, 16, 0) < 16) return undefined;
    if (head.readUInt32LE(0) !== 4) return undefined;
    const headerSize = head.readUInt32LE(4);
    const payloadSize = head.readUInt32LE(8);
    const jsonLen = head.readUInt32LE(12);
    if (payloadSize !== headerSize - 4) return undefined; // pickles must agree
    const jsonTruncated = jsonLen > maxJsonBytes;
    // A header that claims more bytes than the file holds is corrupt/truncated.
    if (16 + jsonLen > fstatSync(fd).size) return undefined;
    if (jsonTruncated) {
      return { jsonLen, headerSize, files: 0, fileEntries: 0, sampleFiles: [], jsonTruncated };
    }
    const buf = Buffer.alloc(jsonLen);
    if (readSync(fd, buf, 0, jsonLen, 16) !== jsonLen) return undefined;
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.toString("utf8"));
    } catch {
      return { jsonLen, headerSize, files: 0, fileEntries: 0, sampleFiles: [], jsonTruncated: false };
    }
    const filesMap = subDict(subDict(parsed)?.["files"]);
    const flat = filesMap !== undefined ? flattenFiles(filesMap, "", 10_000_000) : [];
    return {
      jsonLen,
      headerSize,
      files: flat.length,
      fileEntries: flat.length,
      sampleFiles: flat.slice(0, 8).map((f) => f.rel),
      json: buf.toString("utf8"),
      jsonTruncated: false,
    };
  } catch {
    return undefined;
  } finally {
    closeSync(fd);
  }
}

function subDict(v: unknown): Record<string, unknown> | undefined {
  return !!v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function flattenFiles(node: Record<string, unknown>, prefix: string, cap: number): AsarEntry[] {
  const out: AsarEntry[] = [];
  const visit = (dict: Record<string, unknown>, rel: string): void => {
    for (const [name, value] of Object.entries(dict)) {
      if (out.length >= cap) return;
      const sub = subDict(value);
      const entryRel = rel === "" ? name : rel + "/" + name;
      if (sub === undefined) continue;
      const nested = sub["files"];
      if (nested !== undefined && typeof nested === "object" && nested !== null) {
        visit(nested as Record<string, unknown>, entryRel);
        continue;
      }
      const size = typeof sub["size"] === "number" ? (sub["size"] as number) : NaN;
      const offsetRaw = sub["offset"];
      const offset = typeof offsetRaw === "string" ? parseInt(offsetRaw, 10) : typeof offsetRaw === "number" ? offsetRaw : NaN;
      const integrityRaw = subDict(sub["integrity"]);
      out.push({
        rel: entryRel,
        offset,
        size,
        integrity: integrityRaw === undefined ? undefined : {
          algorithm: typeof integrityRaw["algorithm"] === "string" ? (integrityRaw["algorithm"] as string) : undefined,
          hash: typeof integrityRaw["hash"] === "string" ? (integrityRaw["hash"] as string) : undefined,
          blockSize: typeof integrityRaw["blockSize"] === "number" ? (integrityRaw["blockSize"] as number) : undefined,
          blocks: Array.isArray(integrityRaw["blocks"])
            ? (integrityRaw["blocks"] as unknown[]).filter((b): b is string => typeof b === "string")
            : undefined,
        },
      });
    }
  };
  visit(node, prefix);
  return out;
}

function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

const HEADER_HASH_CAP = 64 * 1024 * 1024;

export interface IntegrityCheck {
  status: "match" | "mismatch" | "invalid";
  recorded?: string;
  computed?: string;
  altComputed?: string;
}

/** Verify the recorded header hash against the proven JSON slice. */
export function verifyHeaderHash(asarPath: string, recorded: string): IntegrityCheck {
  const fd = openSync(asarPath, "r");
  try {
    const head = Buffer.alloc(16);
    if (readSync(fd, head, 0, 16, 0) < 16) return { status: "invalid", recorded };
    const headerSize = head.readUInt32LE(4);
    const jsonLen = head.readUInt32LE(12);
    // Sizes come from an untrusted header: never allocate more than the file
    // holds or the analysis cap. "invalid" is reported as unknown, not as tampering.
    const fileSize = fstatSync(fd).size;
    if (jsonLen > HEADER_HASH_CAP || 16 + jsonLen > fileSize) return { status: "invalid", recorded };
    const slice = Buffer.alloc(jsonLen);
    if (readSync(fd, slice, 0, jsonLen, 16) !== jsonLen) return { status: "invalid", recorded };
    const computed = sha256(slice);
    if (computed === recorded.toLowerCase()) return { status: "match", recorded, computed };
    let altComputed: string | undefined;
    if (headerSize >= 4 && headerSize - 4 <= HEADER_HASH_CAP && 12 + headerSize - 4 <= fileSize) {
      const altPayload = Buffer.alloc(headerSize - 4);
      readSync(fd, altPayload, 0, headerSize - 4, 12);
      altComputed = sha256(altPayload);
    }
    return { status: "mismatch", recorded, computed, altComputed };
  } catch {
    return { status: "invalid", recorded };
  } finally {
    closeSync(fd);
  }
}

export interface PerFileCheck {
  attempted: number;
  verifiedFiles: number;
  mismatchedFiles: Array<{ rel: string; recorded?: string; computed?: string }>;
  /** Entries that could not be read/hashed (range past EOF, I/O error): unknown, not tampering. */
  unreadable: Array<{ rel: string; reason: string }>;
  capReached: boolean;
}

/**
 * Verify per-file (and block) integrity records listed in the header when
 * present. Files without integrity entries are skipped silently — absence is
 * normal, not an error.
 */
export function verifyAsarPerFile(asarPath: string, maxFiles: number): PerFileCheck {
  const res: PerFileCheck = { attempted: 0, verifiedFiles: 0, mismatchedFiles: [], unreadable: [], capReached: false };
  const header = readHeader(asarPath);
  if (header?.json === undefined) return res;
  let parsed: unknown;
  try {
    parsed = JSON.parse(header.json);
  } catch {
    return res;
  }
  const filesMap = subDict(subDict(parsed)?.["files"]);
  if (filesMap === undefined) return res;
  const flat = flattenFiles(filesMap, "", Number.MAX_SAFE_INTEGER);
  const withIntegrity = flat.filter((f) => f.integrity?.hash !== undefined && Number.isFinite(f.offset) && Number.isFinite(f.size));
  if (withIntegrity.length > maxFiles) res.capReached = true;

  const fd = openSync(asarPath, "r");
  const fileSize = fstatSync(fd).size;
  try {
    for (const entry of withIntegrity.slice(0, maxFiles)) {
      res.attempted += 1;
      try {
        const base = 8 + header.headerSize;
        if (entry.size < 0 || entry.offset < 0 || base + entry.offset + entry.size > fileSize) {
          res.unreadable.push({ rel: entry.rel, reason: "entry range is negative or extends past the end of the archive" });
          continue;
        }
        // Stream in chunks: entry.size is attacker-controlled and may be huge.
        const h = createHash("sha256");
        const chunk = Buffer.alloc(1024 * 1024);
        let done = 0;
        let short = false;
        while (done < entry.size) {
          const want = Math.min(chunk.length, entry.size - done);
          const got = readSync(fd, chunk, 0, want, base + entry.offset + done);
          if (got <= 0) {
            short = true;
            break;
          }
          h.update(chunk.subarray(0, got));
          done += got;
        }
        if (short) {
          res.unreadable.push({ rel: entry.rel, reason: "short read" });
          continue;
        }
        const computed = h.digest("hex");
        if (computed.toLowerCase() !== (entry.integrity?.hash ?? "").toLowerCase()) {
          res.mismatchedFiles.push({ rel: entry.rel, recorded: entry.integrity?.hash, computed });
        } else {
          res.verifiedFiles += 1;
        }
      } catch (e) {
        res.unreadable.push({ rel: entry.rel, reason: e instanceof Error ? e.message : "read error" });
      }
    }
  } finally {
    closeSync(fd);
  }
  return res;
}

// ---- Info.plist ⇆ asar resolution -------------------------------------------

/**
 * Resolve a key like "Resources/app.asar" or "app.asar" to an on-disk asar
 * inside bundlePath. Observed key shapes in the wild:
 *   Resources/app.asar, Resources/default_app.asar, plain app.asar — plus
 *   stale keys naming files that no longer exist (seen in a real app).
 */
export function resolveKeyTarget(bundlePath: string, key: string): string | undefined {
  const candidates = [
    join(bundlePath, key),
    join(bundlePath, "Contents", key),
    join(bundlePath, "Contents", "Resources", key),
    join(bundlePath, "Contents", "Resources", key.replace(/^Resources\//, "")),
  ];
  let rootReal: string;
  try {
    rootReal = realpathSync(bundlePath);
  } catch {
    return undefined;
  }
  for (const c of candidates) {
    // Plist keys are untrusted: "../x" or a symlink must not make shipcheck
    // treat (or later read) a file outside the bundle as a bundled asar.
    if (existsSync(c) && containedRealPath(rootReal, c) !== undefined) return c;
  }
  return undefined;
}

export function keyRelative(bundlePath: string, asarPath: string): string {
  const rel = relative(bundlePath, asarPath);
  return rel.length > 0 ? rel : asarPath;
}

/** Scan header JSON for host build paths like /Users/…, /home/…, /tmp/…. */
export function scanHeaderForBuildPaths(asarPath: string, maxMatches = 8): string[] {
  const header = readHeader(asarPath);
  if (header?.json === undefined) return [];
  const matches: string[] = [];
  const re = /\/(?:Users|home|root|tmp|private)\/[A-Za-z0-9_.\-/@]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(header.json)) !== null) {
    matches.push(m[0]);
    if (matches.length >= maxMatches) break;
  }
  return matches;
}
