// ASAR payload checks.
//
// Real-world facts encoded (all verified live on macOS 27):
//   - Info.plist's ElectronAsarIntegrity maps keys like "Resources/app.asar"
//     (ChatGPT.app) or "Resources/default_app.asar" (Cursor.app, LM
//     Studio.app) to {algorithm:"SHA256", hash}. The hash is SHA-256 over
//     file bytes [16, 16+jsonLen).
//   - A real shipping app declares a stale key pointing at a file it no
//     longer ships — a genuine failure class, not a hypothetical.
//   - app.asar may be absent entirely (loose Resources/app tree) — valid
//     Electron layout; Cursor ships that way.

import type { AuditContext } from "./checkscommon.js";
import { GROUP, fail, info, unknown, warn } from "./checkscommon.js";
import { keyRelative, readHeader, resolveKeyTarget, verifyAsarPerFile, verifyHeaderHash } from "./asar.js";
import { asDict, asString, type PlistDict } from "./plist.js";

const S = GROUP.asar;
const PER_FILE_CAP = 2000;

type IntegrityRecord = Record<string, { algorithm: string | undefined; hash: string | undefined }>;

function extractIntegrityRecord(dict: PlistDict | undefined): IntegrityRecord | undefined {
  const raw = asDict(dict?.["ElectronAsarIntegrity"]);
  if (raw === undefined) return undefined;
  const out: IntegrityRecord = {};
  for (const [key, value] of Object.entries(raw)) {
    const sub = asDict(value);
    if (sub !== undefined) {
      out[key] = {
        algorithm: asString(sub["algorithm"]),
        hash: asString(sub["hash"]),
      };
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

export function runAsarChecks(ctx: AuditContext): void {
  const app = ctx.app;
  if (app === undefined) return;

  const dict = app.infoPlist.dict;
  const record = extractIntegrityRecord(dict);

  if (app.asarPaths.length === 0) {
    if (app.looseAppDir !== undefined) {
      ctx.collector.add({
        id: "asar.layout",
        group: S,
        status: "info",
        detail: "No app.asar; payload ships as a loose Resources/app directory (valid Electron layout; bigger read/write surface).",
      });
    } else {
      ctx.collector.add({
        id: "asar.layout",
        group: S,
        status: "warn",
        detail: "Neither app.asar nor a loose Resources/app directory found — payload layout is not a recognizable Electron shape.",
      });
    }
    if (record !== undefined) {
      const missing = Object.keys(record).filter((key) => resolveKeyTarget(app.bundlePath, key) === undefined);
      ctx.collector.add({
        id: "asar.integrity-declared",
        group: S,
        status: "warn",
        detail: missing.length === Object.keys(record).length
          ? `Info.plist declares ElectronAsarIntegrity (${Object.keys(record).join(", ")}) but no referenced asar exists on disk — a stale record; Electron prints runtime integrity errors for it.`
          : "ElectronAsarIntegrity declared but the bundle has no asar payload checked locally.",
        hint: "Rebuild the bundle; stale declarations come from packaging scripts that renamed the payload.",
      });
    }
    return;
  }

  let declaredTotal = 0;

  for (const asarPath of app.asarPaths) {
    const rel = keyRelative(app.bundlePath, asarPath);
    const header = readHeader(asarPath);

    if (header === undefined) {
      ctx.collector.add({
        id: `asar.header:${rel}`,
        group: S,
        status: "fail",
        detail: `Could not parse the ASAR header of ${rel} — archive truncated, corrupt, or not an asar.`,
        evidence: [asarPath],
        hint: "Repackage the payload; do not ship this artifact.",
      });
      continue;
    }
    if (header.jsonTruncated) {
      ctx.collector.add({
        id: `asar.header:${rel}`,
        group: S,
        status: "unknown",
        detail: `ASAR header JSON of ${rel} exceeds the analysis cap (file index ≈${(header.jsonLen / 1024 / 1024).toFixed(1)}MB); structure not checked.`,
        evidence: [`jsonLen=${header.jsonLen}`],
      });
      continue;
    }
    ctx.collector.add({
      id: `asar.header:${rel}`,
      group: S,
      status: "pass",
      detail: `ASAR header parsed: ${header.files} file entries (index ${(header.jsonLen / 1024).toFixed(0)}KB).`,
      evidence: header.sampleFiles.slice(0, 4),
    });

    if (ctx.opts.asarDepth === "files") {
      const perFile = verifyAsarPerFile(asarPath, PER_FILE_CAP);
      if (perFile.attempted === 0) {
        ctx.collector.add({
          id: `asar.files:${rel}`,
          group: S,
          status: "info",
          detail: `No per-file integrity records inside ${rel} — beyond the header there is nothing to verify locally.`,
        });
      } else if (perFile.mismatchedFiles.length === 0 && perFile.unreadable.length > 0) {
        ctx.collector.add(
          unknown(
            `asar.files:${rel}`,
            S,
            `${perFile.unreadable.length} of ${perFile.attempted} sampled asar entries could not be read, so they were not verified (this is not evidence of tampering).`,
            perFile.unreadable.slice(0, 5).map((u) => `${u.rel}: ${u.reason}`),
          ),
        );
      } else if (perFile.mismatchedFiles.length > 0) {
        ctx.collector.add(
          fail(
            `asar.files:${rel}`,
            S,
            `${perFile.mismatchedFiles.length} of ${perFile.attempted} sampled asar entries fail their embedded integrity hash — payload edited after packaging.`,
            perFile.mismatchedFiles.slice(0, 5).map((m) => m.rel),
            "Repackage the payload; content drift inside a signed bundle breaks trust.",
          ),
        );
      } else {
        ctx.collector.add({
          id: `asar.files:${rel}`,
          group: S,
          status: "pass",
          detail: `${perFile.verifiedFiles}/${perFile.attempted} asar entries verified against embedded integrity records${perFile.capReached ? " (capped)" : ""}.`,
        });
      }
    }
  }

  if (record !== undefined) {
    // One result per declared key, labelled by the archive the key resolves to
    // (never by whichever asar the loop happens to be on).
    for (const [key, entry] of Object.entries(record)) {
      if (entry.hash === undefined) continue;
      declaredTotal += 1;
      const target = resolveKeyTarget(app.bundlePath, key);
      if (target === undefined) {
        ctx.collector.add({
          id: `asar.integrity-declared:${key}`,
          group: S,
          status: "warn",
          detail: `ElectronAsarIntegrity declares "${key}" but that file does not exist inside the bundle — stale record (seen in a real shipping Electron app).`,
          hint: "Rebuild; stale keys cause runtime integrity warnings on customer machines.",
        });
        continue;
      }
      const targetRel = keyRelative(app.bundlePath, target);
      const id = `asar.integrity:${targetRel}`;
      if (entry.algorithm !== undefined && !/^sha-?256$/i.test(entry.algorithm)) {
        ctx.collector.add(unknown(id, S, `ElectronAsarIntegrity[${key}] uses algorithm "${entry.algorithm}", which shipcheck does not verify (only SHA256).`, [`algorithm=${entry.algorithm}`]));
        continue;
      }
      const check = verifyHeaderHash(target, entry.hash);
      if (check.status === "match") {
        ctx.collector.add({
          id,
          group: S,
          status: "pass",
          detail: `ElectronAsarIntegrity[${key}] matches the header of ${targetRel} (SHA256). Electron enforces this record only when the EnableEmbeddedAsarIntegrityValidation fuse is enabled; shipcheck does not read fuses, so runtime enforcement is unverified.`,
        });
      } else if (check.status === "mismatch") {
        ctx.collector.add(
          fail(
            id,
            S,
            `ElectronAsarIntegrity[${key}] MISMATCH between Info.plist and the header of ${targetRel} — payload and bundle metadata disagree (half-written archive or tampering).`,
            [`recorded=${check.recorded}`, `computed=${check.computed}`],
            "Do not ship; rebuild from a clean tree.",
          ),
        );
      } else {
        ctx.collector.add(unknown(id, S, `Integrity record for ${key} could not be computed against ${targetRel} (header unreadable or implausible).`, [`recorded=${entry.hash}`]));
      }
    }
  }

  if (record === undefined) {
    ctx.collector.add(
      info(
        "asar.integrity-declared",
        S,
        "No ElectronAsarIntegrity record in Info.plist — payload integrity is not enforced at runtime by the shell.",
        undefined,
        "Electron ≥30 embeds it by default check packaging; electron-builder bundles handle this automatically.",
      ),
    );
  }
  void declaredTotal;
}
