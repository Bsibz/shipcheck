// Bounded, pure-TypeScript ZIP reader. It never executes artifact content and
// never extracts anything itself: it parses the central directory, validates
// every entry name / symlink target / size against explicit limits, and hands
// out a plan. src/temp.ts performs the (confined) writes.
//
// Threat model: the ZIP is untrusted. Defends against absolute paths, ".."
// traversal, backslash and NUL tricks, symlink-then-write escapes, entries that
// collide after case/NFC folding, zip bombs (declared AND actual byte caps),
// entry-count floods and truncated/overlapping records.

import { closeSync, fstatSync, openSync, readSync, statSync, type Stats } from "node:fs";
import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { posix } from "node:path";

export interface ZipLimits {
  maxEntries: number;
  maxTotalBytes: number;
  maxEntryBytes: number;
  /** Per-entry uncompressed/compressed ratio above which an entry is rejected (entries over ratioFloorBytes only). */
  maxRatio: number;
  ratioFloorBytes: number;
  maxNameBytes: number;
  maxSymlinkTargetBytes: number;
  maxCentralDirBytes: number;
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 200_000,
  maxTotalBytes: 8 * 1024 ** 3,
  maxEntryBytes: 2 * 1024 ** 3,
  maxRatio: 1000,
  ratioFloorBytes: 16 * 1024 * 1024,
  maxNameBytes: 1024,
  maxSymlinkTargetBytes: 1024,
  maxCentralDirBytes: 256 * 1024 * 1024,
};

export interface ZipEntry {
  /** Normalized, validated, relative POSIX path (no trailing slash). */
  path: string;
  kind: "file" | "dir" | "symlink";
  method: number;
  compressedSize: number;
  size: number;
  localOffset: number;
  mode: number;
  crc32: number;
  /** Only for symlinks: the validated link target. */
  linkTarget?: string;
}

export interface ZipViolation {
  id:
    | "zip-malformed"
    | "zip-entry-count"
    | "zip-total-size"
    | "zip-entry-size"
    | "zip-ratio"
    | "zip-encrypted"
    | "zip-unsupported-method"
    | "zip-path-traversal"
    | "zip-path-absolute"
    | "zip-path-illegal"
    | "zip-symlink-escape"
    | "zip-special-file"
    | "zip-name-collision";
  detail: string;
  entry?: string;
}

export interface ZipPlan {
  entries: ZipEntry[];
  violations: ZipViolation[];
  /** AppleDouble / __MACOSX entries skipped (resource-fork shadows; not extracted). */
  skippedMetadata: number;
  totalUncompressed: number;
  archiveBytes: number;
  entryCount: number;
}

const SIG_EOCD = 0x06054b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_LOC64 = 0x07064b50;
const SIG_CEN = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

function readAt(fd: number, pos: number, len: number): Buffer {
  const buf = Buffer.alloc(len);
  let got = 0;
  while (got < len) {
    const n = readSync(fd, buf, got, len - got, pos + got);
    if (n <= 0) break;
    got += n;
  }
  if (got < len) throw new Error("short read (truncated archive)");
  return buf;
}

function u64(buf: Buffer, off: number): number {
  const v = buf.readBigUInt64LE(off);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("64-bit value out of range");
  return Number(v);
}

/** Validates an entry name; returns normalized path or a violation. */
export function checkEntryName(raw: string, limits: ZipLimits = DEFAULT_ZIP_LIMITS): { path: string } | ZipViolation {
  if (Buffer.byteLength(raw) > limits.maxNameBytes) return { id: "zip-path-illegal", detail: "entry name too long", entry: raw.slice(0, 80) };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { id: "zip-path-illegal", detail: "entry name contains control characters or NUL", entry: JSON.stringify(raw.slice(0, 80)) };
  if (raw.includes("\\")) return { id: "zip-path-illegal", detail: "entry name contains a backslash", entry: raw.slice(0, 80) };
  if (raw.startsWith("/") || /^[A-Za-z]:/.test(raw)) return { id: "zip-path-absolute", detail: "absolute entry path", entry: raw.slice(0, 80) };
  const stripped = raw.endsWith("/") ? raw.slice(0, -1) : raw;
  const parts = stripped.split("/");
  if (parts.some((p) => p === "..")) return { id: "zip-path-traversal", detail: "entry path contains '..'", entry: raw.slice(0, 80) };
  const clean = parts.filter((p) => p !== "." && p !== "");
  if (clean.length === 0) return { id: "zip-path-illegal", detail: "empty entry path", entry: raw.slice(0, 80) };
  return { path: clean.join("/") };
}

function isViolation(v: { path: string } | ZipViolation): v is ZipViolation {
  return "id" in v;
}

/** Resolve a symlink target relative to its link location; true if it stays inside the root. */
export function symlinkStaysInside(linkPath: string, target: string): boolean {
  if (target.length === 0 || target.startsWith("/") || target.includes("\0") || target.includes("\\")) return false;
  const base = posix.dirname(linkPath);
  const resolved = posix.normalize(posix.join(base === "." ? "" : base, target));
  return resolved !== ".." && !resolved.startsWith("../") && !resolved.startsWith("/");
}

function foldKey(p: string): string {
  return p.normalize("NFC").toLowerCase();
}

// ---- audited-bytes pinning -----------------------------------------------------

export interface ZipIdentity {
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
}

function identityOf(st: Stats): ZipIdentity {
  return { dev: st.dev, ino: st.ino, size: st.size, mtimeMs: st.mtimeMs };
}

function sameIdentity(a: ZipIdentity, b: ZipIdentity): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs;
}

/**
 * One open descriptor for the whole audit: planning, extraction and the
 * receipt's SHA-256 all read THIS fd, so the hash describes the audited bytes.
 * `changed()` compares the fd's and the path's current identity (dev, inode,
 * size, mtime) with the identity captured at open; any drift means a ZIP
 * swapped or rewritten mid-audit.
 */
export interface PinnedZip {
  fd: number;
  identity: ZipIdentity;
  /** SHA-256 of the file bytes read through `fd`, taken before any parsing. */
  sha256: string;
  changed(): boolean;
  close(): void;
}

export function pinZip(zipPath: string): PinnedZip {
  const fd = openSync(zipPath, "r");
  try {
    const identity = identityOf(fstatSync(fd));
    const h = createHash("sha256");
    const buf = Buffer.alloc(1024 * 1024);
    let pos = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, pos);
      if (n <= 0) break;
      h.update(buf.subarray(0, n));
      pos += n;
    }
    if (pos !== identity.size) throw new Error("ZIP size changed while it was being read");
    let closed = false;
    return {
      fd,
      identity,
      sha256: h.digest("hex"),
      changed(): boolean {
        try {
          if (!closed && !sameIdentity(identity, identityOf(fstatSync(fd)))) return true;
          return !sameIdentity(identity, identityOf(statSync(zipPath)));
        } catch {
          return true;
        }
      },
      close(): void {
        if (closed) return;
        closed = true;
        closeSync(fd);
      },
    };
  } catch (e) {
    closeSync(fd);
    throw e;
  }
}

// ---- CRC-32 ---------------------------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = (CRC_TABLE[(c ^ (buf[i] as number)) & 0xff] as number) ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function planZip(zip: string | number, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipPlan {
  const violations: ZipViolation[] = [];
  const plan: ZipPlan = { entries: [], violations, skippedMetadata: 0, totalUncompressed: 0, archiveBytes: 0, entryCount: 0 };
  const ownsFd = typeof zip === "string";
  const fd = typeof zip === "string" ? openSync(zip, "r") : zip;
  try {
    const size = fstatSync(fd).size;
    plan.archiveBytes = size;
    if (size < 22) {
      violations.push({ id: "zip-malformed", detail: "file too small to be a ZIP" });
      return plan;
    }
    const tailLen = Math.min(size, 22 + 65535);
    const tail = readAt(fd, size - tailLen, tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i -= 1) {
      if (tail.readUInt32LE(i) === SIG_EOCD) {
        const commentLen = tail.readUInt16LE(i + 20);
        if (i + 22 + commentLen === tail.length) {
          eocd = i;
          break;
        }
      }
    }
    if (eocd < 0) {
      violations.push({ id: "zip-malformed", detail: "end-of-central-directory record not found" });
      return plan;
    }
    let total = tail.readUInt16LE(eocd + 10);
    let cdSize = tail.readUInt32LE(eocd + 12);
    let cdOff = tail.readUInt32LE(eocd + 16);
    if (total === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) {
      const locPos = size - tailLen + eocd - 20;
      if (locPos < 0) {
        violations.push({ id: "zip-malformed", detail: "ZIP64 locator missing" });
        return plan;
      }
      const loc = readAt(fd, locPos, 20);
      if (loc.readUInt32LE(0) !== SIG_LOC64) {
        violations.push({ id: "zip-malformed", detail: "ZIP64 locator invalid" });
        return plan;
      }
      const e64pos = u64(loc, 8);
      const e64 = readAt(fd, e64pos, 56);
      if (e64.readUInt32LE(0) !== SIG_EOCD64) {
        violations.push({ id: "zip-malformed", detail: "ZIP64 end record invalid" });
        return plan;
      }
      total = u64(e64, 32);
      cdSize = u64(e64, 40);
      cdOff = u64(e64, 48);
    }
    plan.entryCount = total;
    if (total > limits.maxEntries) {
      violations.push({ id: "zip-entry-count", detail: `archive declares ${total} entries (limit ${limits.maxEntries})` });
      return plan;
    }
    if (cdSize > limits.maxCentralDirBytes || cdOff + cdSize > size) {
      violations.push({ id: "zip-malformed", detail: "central directory size/offset out of bounds" });
      return plan;
    }
    const cd = readAt(fd, cdOff, cdSize);

    const seen = new Map<string, string>();
    const symlinkIdx: ZipEntry[] = [];
    let pos = 0;
    for (let n = 0; n < total; n += 1) {
      if (pos + 46 > cd.length || cd.readUInt32LE(pos) !== SIG_CEN) {
        violations.push({ id: "zip-malformed", detail: `central directory record ${n} is invalid or truncated` });
        return plan;
      }
      const flags = cd.readUInt16LE(pos + 8);
      const method = cd.readUInt16LE(pos + 10);
      const crc32 = cd.readUInt32LE(pos + 16);
      let csize = cd.readUInt32LE(pos + 20);
      let usize = cd.readUInt32LE(pos + 24);
      const nameLen = cd.readUInt16LE(pos + 28);
      const extraLen = cd.readUInt16LE(pos + 30);
      const commentLen = cd.readUInt16LE(pos + 32);
      const versionMadeBy = cd.readUInt16LE(pos + 4);
      const extAttr = cd.readUInt32LE(pos + 38);
      let lho = cd.readUInt32LE(pos + 42);
      const end = pos + 46 + nameLen + extraLen + commentLen;
      if (end > cd.length) {
        violations.push({ id: "zip-malformed", detail: `central directory record ${n} overruns the directory` });
        return plan;
      }
      const rawName = cd.subarray(pos + 46, pos + 46 + nameLen).toString((flags & 0x800) !== 0 ? "utf8" : "utf8");
      if (csize === 0xffffffff || usize === 0xffffffff || lho === 0xffffffff) {
        let ep = pos + 46 + nameLen;
        const eend = ep + extraLen;
        while (ep + 4 <= eend) {
          const id = cd.readUInt16LE(ep);
          const sz = cd.readUInt16LE(ep + 2);
          if (id === 0x0001) {
            let o = ep + 4;
            if (usize === 0xffffffff) { usize = u64(cd, o); o += 8; }
            if (csize === 0xffffffff) { csize = u64(cd, o); o += 8; }
            if (lho === 0xffffffff) { lho = u64(cd, o); o += 8; }
          }
          ep += 4 + sz;
        }
      }
      pos = end;

      const mode = versionMadeBy >> 8 === 3 ? (extAttr >>> 16) & 0xffff : 0;
      const fmt = mode & 0o170000;
      const nameCheck = checkEntryName(rawName, limits);
      if (isViolation(nameCheck)) {
        violations.push(nameCheck);
        continue;
      }
      const path = nameCheck.path;
      if ((flags & 1) !== 0) {
        violations.push({ id: "zip-encrypted", detail: "encrypted entry cannot be audited", entry: path });
        continue;
      }
      if (path.split("/")[0] === "__MACOSX" || posix.basename(path).startsWith("._")) {
        plan.skippedMetadata += 1;
        continue;
      }
      let kind: ZipEntry["kind"];
      if (rawName.endsWith("/") || fmt === 0o040000) kind = "dir";
      else if (fmt === 0o120000) kind = "symlink";
      else if (fmt === 0 || fmt === 0o100000) kind = "file";
      else {
        violations.push({ id: "zip-special-file", detail: `special file type 0${fmt.toString(8)} (device/fifo/socket)`, entry: path });
        continue;
      }
      if (kind !== "dir" && method !== 0 && method !== 8) {
        violations.push({ id: "zip-unsupported-method", detail: `compression method ${method} is not supported`, entry: path });
        continue;
      }
      if (usize > limits.maxEntryBytes) {
        violations.push({ id: "zip-entry-size", detail: `entry declares ${usize} bytes (limit ${limits.maxEntryBytes})`, entry: path });
        continue;
      }
      if (usize >= limits.ratioFloorBytes && usize / Math.max(csize, 1) > limits.maxRatio) {
        violations.push({ id: "zip-ratio", detail: `compression ratio ${Math.round(usize / Math.max(csize, 1))}:1 exceeds ${limits.maxRatio}:1`, entry: path });
        continue;
      }
      plan.totalUncompressed += usize;
      if (plan.totalUncompressed > limits.maxTotalBytes) {
        violations.push({ id: "zip-total-size", detail: `declared uncompressed total exceeds ${limits.maxTotalBytes} bytes` });
        return plan;
      }
      if (lho + 30 > size || csize > size) {
        violations.push({ id: "zip-malformed", detail: "entry offset/size out of archive bounds", entry: path });
        continue;
      }
      const key = foldKey(path);
      const prior = seen.get(key);
      if (prior !== undefined) {
        violations.push({ id: "zip-name-collision", detail: `entry collides with "${prior}" after case/Unicode folding`, entry: path });
        continue;
      }
      seen.set(key, path);
      const entry: ZipEntry = { path, kind, method, compressedSize: csize, size: usize, localOffset: lho, mode, crc32 };
      if (kind === "symlink") symlinkIdx.push(entry);
      plan.entries.push(entry);
    }

    // Symlink targets: read (bounded) and confine.
    for (const e of symlinkIdx) {
      if (e.size > limits.maxSymlinkTargetBytes) {
        violations.push({ id: "zip-symlink-escape", detail: "symlink target too long", entry: e.path });
        continue;
      }
      try {
        const target = readEntryBytes(fd, e, limits.maxSymlinkTargetBytes).toString("utf8");
        e.linkTarget = target;
        if (!symlinkStaysInside(e.path, target)) {
          violations.push({ id: "zip-symlink-escape", detail: `symlink target "${target.slice(0, 120)}" escapes the archive root`, entry: e.path });
        }
      } catch (err) {
        violations.push({ id: "zip-malformed", detail: `symlink data unreadable: ${(err as Error).message}`, entry: e.path });
      }
    }
    // A file or dir placed beneath a symlink entry is the classic write-through escape.
    const linkPaths = new Set(symlinkIdx.map((e) => e.path));
    for (const e of plan.entries) {
      const parts = e.path.split("/");
      for (let i = 1; i < parts.length; i += 1) {
        const parent = parts.slice(0, i).join("/");
        if (linkPaths.has(parent)) {
          violations.push({ id: "zip-symlink-escape", detail: `entry is nested under symlink "${parent}"`, entry: e.path });
          break;
        }
      }
    }
    return plan;
  } finally {
    if (ownsFd) closeSync(fd);
  }
}

/** Read and fully decompress one entry, enforcing the declared size exactly (no more, no less). */
export function readEntryBytes(fd: number, e: ZipEntry, hardCap: number): Buffer {
  if (e.size > hardCap) throw new Error("entry exceeds in-memory cap");
  const lh = readAt(fd, e.localOffset, 30);
  if (lh.readUInt32LE(0) !== SIG_LOCAL) throw new Error("bad local header");
  const dataStart = e.localOffset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  const raw = readAt(fd, dataStart, e.compressedSize);
  const out = e.method === 0 ? raw : inflateRawSync(raw, { maxOutputLength: Math.max(e.size, 1) });
  if (out.length !== e.size) throw new Error("decompressed size does not match declared size");
  if (crc32(out) !== e.crc32) throw new Error(`CRC-32 mismatch (corrupt or altered entry data)`);
  return out;
}

export { SIG_LOCAL };
