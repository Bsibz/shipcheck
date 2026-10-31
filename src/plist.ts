// Minimal, dependency-free Apple XML plist reader.
//
// Scope: well-formed plists as produced by Apple tooling (codesign output,
// handwritten Info.plist test fixtures). Supports dict/array/string/integer/
// real/true/false/date. <data> and unknown nodes are skipped and counted,
// because shipcheck only needs identity strings, URLs and integrity dicts.
//
// Binary plists are never parsed here; callers normalize with plutil when
// needed.

export type PlistValue = string | number | boolean | PlistDict | PlistValue[] | PlistDate;

export interface PlistDate {
  __date: string;
}

export interface PlistDict {
  [key: string]: PlistValue | undefined;
}

export function asDict(v: unknown): PlistDict | undefined {
  return !!v && typeof v === "object" && !Array.isArray(v) ? (v as PlistDict) : undefined;
}

export function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

export function getString(dict: PlistDict | undefined, key: string): string | undefined {
  return asString(dict?.[key]);
}

export interface ParseResult {
  ok: boolean;
  value?: PlistValue;
  error?: string;
  skippedNodes: number;
}

const ENTITIES: Record<string, string> = {
  "&lt;": "<",
  "&gt;": ">",
  "&amp;": "&",
  "&quot;": '"',
  "&apos;": "'",
};

function decodeEntities(s: string): string {
  let out = "";
  let i = 0;
  while (i < s.length) {
    const amp = s.indexOf("&", i);
    if (amp === -1) {
      out += s.slice(i);
      break;
    }
    out += s.slice(i, amp);
    const semi = s.indexOf(";", amp);
    if (semi === -1) {
      out += "&";
      i = amp + 1;
      continue;
    }
    const tok = s.slice(amp, semi + 1);
    if (tok in ENTITIES) {
      out += ENTITIES[tok]!;
    } else if (/^&#x[0-9a-fA-F]+;$/.test(tok)) {
      out += String.fromCodePoint(parseInt(tok.slice(3, -1), 16));
    } else if (/^&#\d+;$/.test(tok)) {
      out += String.fromCodePoint(parseInt(tok.slice(2, -1), 10));
    } else {
      out += tok;
    }
    i = semi + 1;
  }
  return out;
}

type Token =
  | { kind: "start"; name: string }
  | { kind: "end"; name: string }
  | { kind: "text"; text: string };

function tokenize(xml: string): Token[] {
  const tokens: Token[] = [];
  const re = /<!--[\s\S]*?-->|<\/?[A-Za-z][A-Za-z0-9._-]*[^>]*>|[^<]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    const raw = m[0];
    if (raw.startsWith("<!--")) continue;
    if (raw.startsWith("<")) {
      if (raw.startsWith("</")) {
        tokens.push({ kind: "end", name: raw.slice(2, -1).trim() });
      } else if (raw.endsWith("/>") && raw.indexOf(" ") === -1) {
        const name = raw.slice(1, -2).trim();
        tokens.push({ kind: "start", name });
        tokens.push({ kind: "end", name });
      } else {
        const name = raw.includes(" ") ? raw.slice(1).replace(/\/>$/, "").replace(/>$/, "").trim().split(/\s+/)[0]! : raw.slice(1).replace(/\/>$/, "").replace(/>$/, "").trim().split(/\s+/)[0]!;
        tokens.push({ kind: "start", name });
        if (raw.endsWith("/>")) tokens.push({ kind: "end", name });
      }
    } else {
      tokens.push({ kind: "text", text: decodeEntities(raw) });
    }
  }
  return tokens;
}

interface Frame {
  tag: string;
  dict?: PlistDict;
  arr?: PlistValue[];
  pendingKey?: string;
  /** Text accumulated inside a leaf node (string/integer/real/date). */
  text?: string;
}

const LEAF_TAGS: ReadonlySet<string> = new Set(["string", "integer", "real", "true", "false", "date", "data", "key"]);

export function parsePlistXml(xml: string): ParseResult {
  const tokens = tokenize(xml);
  const stack: Frame[] = [];
  const rootValues: PlistValue[] = [];
  let skippedNodes = 0;

  const emit = (value: PlistValue): void => {
    const top = stack[stack.length - 1];
    if (!top) {
      rootValues.push(value);
      return;
    }
    if (top.tag === "dict") {
      if (top.pendingKey === undefined) {
        skippedNodes += 1;
      } else {
        top.dict![top.pendingKey] = value;
        top.pendingKey = undefined;
      }
    } else if (top.tag === "array") {
      top.arr!.push(value);
    } else if (top.tag === "plist" || top.tag === "main") {
      // the <plist> wrapper carries no key/value structure
      rootValues.push(value);
    } else {
      skippedNodes += 1;
    }
  };

  for (const t of tokens) {
    if (t.kind === "start") {
      if (LEAF_TAGS.has(t.name)) stack.push({ tag: t.name });
      else if (t.name === "dict") stack.push({ tag: "dict", dict: {} });
      else if (t.name === "array") stack.push({ tag: "array", arr: [] });
      else stack.push({ tag: t.name });
      continue;
    }
    if (t.kind === "text") {
      const top = stack[stack.length - 1];
      if (!top) continue;
      if (top.tag === "string" || top.tag === "integer" || top.tag === "real" || top.tag === "date" || top.tag === "key") {
        top.text = (top.text ?? "") + t.text;
      } else if (top.tag === "data") {
        skippedNodes += 1;
      }
      continue;
    }
    // end tag
    const frame = stack.pop();
    if (!frame || frame.tag !== t.name) continue;
    if (frame.tag === "true") emit(true);
    else if (frame.tag === "false") emit(false);
    else if (frame.tag === "data") continue;
    else if (frame.tag === "string" || frame.tag === "date") emit(frame.text ?? "");
    else if (frame.tag === "integer") {
      const n = parseInt((frame.text ?? "").trim(), 10);
      emit(Number.isNaN(n) ? 0 : n);
    } else if (frame.tag === "real") {
      const n = parseFloat((frame.text ?? "").trim());
      emit(Number.isNaN(n) ? 0 : n);
    } else if (frame.tag === "key") {
      // keys are stored on the enclosing dict frame, not emitted as values
      const parent = stack[stack.length - 1];
      if (parent !== undefined && parent.tag === "dict") {
        if (parent.pendingKey !== undefined) skippedNodes += 1;
        parent.pendingKey = frame.text ?? "";
      } else {
        skippedNodes += 1;
      }
    } else if (frame.tag === "dict" || frame.tag === "array") {
      emit(frame.tag === "dict" ? frame.dict! : frame.arr!);
    }
  }

  const root = rootValues[0];
  if (rootValues.length === 0) {
    return { ok: false, error: "no root value parsed", skippedNodes };
  }
  return { ok: true, value: root, skippedNodes };
}
