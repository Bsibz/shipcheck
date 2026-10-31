// Entitlements and hardened-runtime checks.
//
// Facts captured live (macOS 27):
//   - `codesign -d --entitlements :- <path>` prints XML on stdout when the
//     binary has entitlements and nothing when it has none (a deprecation
//     warning appears on stderr — harmless).
//   - Hardened runtime appears in `flags=0x...(...,runtime,...)`.
//   - Electron/V8 JIT under hardened runtime needs com.apple.security.cs.
//     allow-jit OR allow-unsigned-executable-memory; an Electron main binary
//     with hardened runtime and NEITHER is a launch-breaking misconfig.

import { existsSync } from "node:fs";
import type { AuditContext } from "./checkscommon.js";
import { GROUP, fail, info, unknown, warn } from "./checkscommon.js";
import { displayEntitlements, displayInfo, type CodeInfo } from "./codesign.js";

const E = GROUP.entitlements;

export interface EntitlementFacts {
  present: boolean;
  dict?: Record<string, unknown>;
  hardenedRuntime: boolean;
}

export function runEntitlements(ctx: AuditContext): EntitlementFacts | undefined {
  const app = ctx.app;
  if (app === undefined) return undefined;

  const display: CodeInfo = displayInfo(app.execPath ?? app.bundlePath, ctx.params);
  if (display.toolUnavailable !== undefined) {
    ctx.collector.add(unknown("ent.hardened", E, `Hardened runtime could not be determined: ${display.toolUnavailable}.`, [display.toolUnavailable]));
    return undefined;
  }
  if (display.notSigned) {
    // Entitlements of an unsigned binary are meaningless; checks-identity
    // already fails the release. Record and move on.
    ctx.collector.add({
      id: "ent.hardened",
      group: E,
      status: "skip",
      detail: "Entitlements skipped: binary is unsigned.",
    });
    return undefined;
  }

  const hard = display.hardenedRuntime;
  ctx.collector.add(
    hard
      ? { id: "ent.hardened", group: E, status: "pass" as const, detail: "Hardened runtime is enabled (flags include runtime)." }
      : fail("ent.hardened", E, "Hardened runtime NOT enabled — notarization is impossible and Gatekeeper treats the app as less trustworthy.", undefined, "Sign with --options runtime."),
  );

  if (!existsSync(app.execPath ?? "")) {
    ctx.collector.add(warn("ent.analysis", E, "Entitlements not analyzed: main executable missing."));
    return undefined;
  }
  const ent = displayEntitlements(app.execPath ?? "", ctx.params);
  if (ent.error !== undefined && !ent.present) {
    ctx.collector.add(unknown("ent.entitlements", E, `Entitlements could not be read: ${ent.error}.`, [ent.error]));
    return { present: false, hardenedRuntime: hard };
  }
  if (!ent.present) {
    // Electron main binaries usually carry allow-jit; absence is only
    // interesting if the runtime is hardened.
    if (hard && app.helperApps.length > 0) {
      ctx.collector.add(
        warn(
          "ent.entitlements",
          E,
          "Hardened runtime enabled but the main binary reports no embedded entitlements in its signature.",
          ["codesign -d --entitlements :- : empty"],
          "If this binary runs V8/Electron in-process, JIT requires an explicit entitlement — verify the build actually runs.",
        ),
      );
    } else {
      ctx.collector.add(info("ent.entitlements", E, "No embedded entitlements in the main executable's signature."));
    }
    return { present: false, hardenedRuntime: hard };
  }

  const dict = ent.dict as Record<string, unknown>;
  const keys = Object.keys(dict);
  ctx.collector.add({
    id: "ent.entitlements",
    group: E,
    status: "pass",
    detail: `Main executable carries ${keys.length} entitlement(s).`,
    evidence: keys.slice(0, 12).map((k) => `${k}`),
  });

  if (hard) {
    const jitOK = dict["com.apple.security.cs.allow-jit"] === true || dict["com.apple.security.cs.allow-unsigned-executable-memory"] === true;
    if (jitOK) {
      ctx.collector.add({
        id: "ent.jit",
        group: E,
        status: "pass",
        detail: dict["com.apple.security.cs.allow-jit"] === true
          ? "V8 JIT path allowed (com.apple.security.cs.allow-jit)."
          : "JIT permitted via allow-unsigned-executable-memory (legacy path).",
      });
    } else if (keys.some((k) => k.startsWith("com.apple.security.cs."))) {
      ctx.collector.add({
        id: "ent.jit",
        group: E,
        status: "warn",
        detail: "Hardened runtime + some security entitlements, but no JIT permission. This is fine unless the app runs V8 in this binary.",
        hint: "Electron processes usually need allow-jit. Double-check the app actually launches under hardened runtime.",
      });
    } else {
      ctx.collector.add(warn("ent.jit", E, "Hardened runtime without any code-security entitlements — acceptable for non-V8 apps; verify launch under hardened runtime."));
    }
  }

  // Dangerous trust entitlements are worth surfacing (they widen attack surface)
  const notable: string[] = [];
  for (const key of keys) {
    if (/com\.apple\.security\.get-task-allow/.test(key)) notable.push(`${key}=true — DEBUG task port OPEN in a release build`);
    if (/com\.apple\.security\.cs\.disable-library-validation/.test(key)) notable.push(`${key}=true — any signed library can load`);
    if (/com\.apple\.keychain/.test(key)) notable.push(`${key} — keychain family grant`);
  }
  if (notable.length > 0) {
    ctx.collector.add(
      warn(
        "ent.risky",
        E,
        "Potentially risky entitlements detected in a release build:",
        notable.slice(0, 6),
        "get-task-allow in a release is a debugger hook; strip it from customer builds.",
      ),
    );
  }

  return { present: true, dict, hardenedRuntime: hard };
}
