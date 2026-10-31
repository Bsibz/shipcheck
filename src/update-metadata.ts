// Bounded field inspection, not a general YAML/XML validator. No feed fetches,
// entity expansion, artifact loading, or updater execution. Values stay private.
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename } from "node:path";

export const MAX_UPDATE_METADATA_BYTES = 256 * 1024;
export interface UpdateMetadata {
  name: string;
  kind: "latest-mac" | "appcast" | "unsupported";
  sha256?: string;
  entries: number;
  problems: string[];
  unknown?: string;
}

function scalar(raw: string): string | undefined {
  const s = raw.trim();
  if (s.startsWith('"')) { try { const v: unknown = JSON.parse(s); return typeof v === "string" ? v : undefined; } catch { return undefined; } }
  if (s.startsWith("'")) return /^'(?:[^']|'')*'$/.test(s) ? s.slice(1, -1).replaceAll("''", "'") : undefined;
  if (/^[!&*\[\]{}|>]/.test(s)) return undefined;
  return s.replace(/\s+#.*$/, "").trim();
}
function digest64(s: string | undefined): boolean {
  return s !== undefined && /^[A-Za-z0-9+/]{86}==$/.test(s) && Buffer.from(s, "base64").length === 64;
}
function location(s: string | undefined): "secure" | "insecure" | "unsupported" {
  if (!s) return "unsupported";
  if (/^https?:\/\//i.test(s)) {
    try { const u = new URL(s); return u.protocol === "https:" && !u.username && !u.password ? "secure" : "insecure"; } catch { return "unsupported"; }
  }
  // Relative release filenames only. Never resolve/read these local targets.
  try {
    const p = decodeURIComponent(s);
    return !p.startsWith("/") && !p.includes("\\") && !p.split("/").includes("..") && !/[:\u0000-\u0020]/.test(p) ? "secure" : "unsupported";
  } catch { return "unsupported"; }
}

export function inspectLatestMac(text: string): Omit<UpdateMetadata, "name" | "kind"> {
  const top = new Map<string, string | undefined>();
  const files: Map<string, string | undefined>[] = [];
  let inFiles = false;
  let current: Map<string, string | undefined> | undefined;
  let ambiguous = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || /^\s*#/.test(line) || line === "---") continue;
    if (line.includes("\t")) { ambiguous = true; continue; }
    const m = /^([A-Za-z][\w-]*):(?:\s+(.*))?$/.exec(line);
    if (m) {
      const key = m[1]!;
      if (top.has(key)) ambiguous = true;
      top.set(key, scalar(m[2] ?? ""));
      inFiles = key === "files";
      if (inFiles && (m[2] ?? "").trim() !== "") ambiguous = true;
      continue;
    }
    if (!inFiles) continue; // release notes and unrelated fields are opaque
    const item = /^  - ([A-Za-z][\w-]*):\s*(.*)$/.exec(line);
    const field = /^    ([A-Za-z][\w-]*):\s*(.*)$/.exec(line);
    if (item) { current = new Map(); files.push(current); }
    const kv = item ?? field;
    if (!kv || !current) { ambiguous = true; continue; }
    if (current.has(kv[1]!)) ambiguous = true;
    current.set(kv[1]!, scalar(kv[2]!));
    if (files.length > 100) return { entries: files.length, problems: [], unknown: "More than 100 release entries; metadata inspection capped." };
  }
  if (ambiguous) return { entries: files.length, problems: [], unknown: "Unsupported or ambiguous YAML layout; only conventional electron-builder block fields are inspected." };
  const problems: string[] = [];
  if (!top.get("version")) problems.push("version field absent or not a supported scalar");
  const releases = files.length > 0 ? files : top.has("path") ? [new Map([["url", top.get("path")], ["sha512", top.get("sha512")]])] : [];
  if (releases.length === 0) problems.push("no release file entries observed");
  for (const file of releases) {
    const loc = location(file.get("url"));
    if (loc !== "secure") problems.push(loc === "insecure" ? "release URL uses HTTP or embedded credentials" : "release location absent or unsupported");
    if (!digest64(file.get("sha512"))) problems.push("release sha512 absent or not a 64-byte base64 digest");
    if (file.has("size") && !/^[1-9]\d*$/.test(file.get("size") ?? "")) problems.push("release size is not a positive integer");
  }
  if (top.has("path") && (location(top.get("path")) !== "secure" || !digest64(top.get("sha512")))) problems.push("legacy path/sha512 fields are incomplete or unsafe");
  return { entries: releases.length, problems: [...new Set(problems)] };
}

function xmlValue(s: string): string | undefined {
  if (/&(?!amp;|quot;|apos;|lt;|gt;)/.test(s)) return undefined;
  return s.replace(/&(amp|quot|apos|lt|gt);/g, (_, k: string) => ({ amp: "&", quot: '"', apos: "'", lt: "<", gt: ">" })[k]!);
}
export function inspectAppcast(text: string): Omit<UpdateMetadata, "name" | "kind"> {
  if (/<!DOCTYPE|<!ENTITY|<!\[CDATA\[/i.test(text)) return { entries: 0, problems: [], unknown: "DTD, entity or CDATA content is outside the appcast field inspector." };
  const xml = text.replace(/<!--[\s\S]*?-->/g, "");
  if (!/<rss(?:\s|>)/.test(xml) || !/<channel(?:\s|>)/.test(xml) || !/<\/channel\s*>/.test(xml) || !/<\/rss\s*>/.test(xml)) return { entries: 0, problems: [], unknown: "RSS/channel wrapper not recognized; appcast syntax is not validated." };
  if (!/xmlns:sparkle\s*=\s*["']http:\/\/www\.andymatuschak\.org\/xml-namespaces\/sparkle["']/.test(xml)) return { entries: 0, problems: [], unknown: "Conventional Sparkle namespace prefix not recognized." };
  const items = [...xml.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item\s*>/g)];
  const enclosures = items.flatMap((item) => [...item[1]!.matchAll(/<enclosure\b([^<>]*)\/?\s*>/g)].map((enc) => ({ enc, item: item[1]! })));
  if (enclosures.length > 100) return { entries: enclosures.length, problems: [], unknown: "More than 100 enclosures; metadata inspection capped." };
  const problems: string[] = [];
  if (!enclosures.length) problems.push("no release enclosures observed");
  for (const { enc, item } of enclosures) {
    const attrs = new Map<string, string | undefined>();
    let ambiguous = false;
    const remainder = enc[1]!.replace(/([\w:.-]+)\s*=\s*(?:"([^"<>]*)"|'([^'<>]*)')/g, (_, key: string, a: string | undefined, b: string | undefined) => {
      if (attrs.has(key)) ambiguous = true;
      attrs.set(key, xmlValue(a ?? b ?? ""));
      return "";
    }).replace(/\/$/, "").trim();
    if (ambiguous || remainder || [...attrs.values()].some((v) => v === undefined)) return { entries: enclosures.length, problems: [], unknown: "Unsupported or ambiguous enclosure attributes; XML validity remains unknown." };
    if (location(attrs.get("url")) !== "secure") problems.push("enclosure URL absent, insecure or unsupported");
    if (!attrs.get("sparkle:version") && !/<sparkle:version>[^<>]+<\/sparkle:version>/.test(item)) problems.push("sparkle:version not observed on item or enclosure");
    if (!/^[1-9]\d*$/.test(attrs.get("length") ?? "")) problems.push("enclosure length absent or not a positive integer");
    if (!digest64(attrs.get("sparkle:edSignature"))) problems.push("64-byte Sparkle EdDSA signature not observed; legacy/alternate signatures are outside this subset");
  }
  return { entries: enclosures.length, problems: [...new Set(problems)] };
}

export function inspectUpdateMetadata(path: string): UpdateMetadata {
  const name = basename(path);
  const kind = /^latest-mac(?:[-.].*)?\.ya?ml$/i.test(name) ? "latest-mac" : /\.xml$/i.test(name) ? "appcast" : "unsupported";
  const base: UpdateMetadata = { name, kind, entries: 0, problems: [] };
  if (kind === "unsupported") return { ...base, unknown: "Only latest-mac YAML and appcast XML field inspection is supported." };
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_UPDATE_METADATA_BYTES) return { ...base, unknown: "Metadata must be a regular file no larger than 256 KiB; symlinks are refused." };
    const bytes = Buffer.alloc(st.size + 1);
    const n = readSync(fd, bytes, 0, bytes.length, 0);
    const after = fstatSync(fd);
    if (n !== st.size || st.size !== after.size || st.mtimeMs !== after.mtimeMs || st.ctimeMs !== after.ctimeMs) return { ...base, unknown: "Metadata changed during its bounded read." };
    const raw = bytes.subarray(0, n);
    const parsed = kind === "latest-mac" ? inspectLatestMac(raw.toString("utf8")) : inspectAppcast(raw.toString("utf8"));
    return { ...base, ...parsed, sha256: createHash("sha256").update(raw).digest("hex") };
  } catch {
    return { ...base, unknown: "Metadata could not be read as a local regular file; contents and errors are redacted." };
  } finally { if (fd !== undefined) closeSync(fd); }
}
