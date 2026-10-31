// Bundle identity & version checks.
//
// Lessons encoded (generic): missing/placeholder version fields, missing
// CFBundleIdentifier, a CFBundleExecutable pointing at nothing, missing
// LSMinimumSystemVersion, and helper apps whose identity disagrees with the
// main bundle — a classic "which build is this?" trap in Electron release
// trees.

import { basename } from "node:path";
import { existsSync, statSync } from "node:fs";
import type { AuditContext } from "./checkscommon.js";
import { GROUP, fail, info, unknown, warn } from "./checkscommon.js";
import { getString } from "./plist.js";
import { readAppStructure, type AppStructure } from "./bundle.js";
import { classifyAdhoc, classifyAuthority, displayInfo, verifyDeveloperIdRequirement, verifyStrict, type CodeInfo, type VerifyResult } from "./codesign.js";

const G = GROUP.identity;
const S = GROUP.signing;

const DEGENERATE_VERSIONS = new Set(["", "0", "0.0", "0.0.0", "1.0", "999"]);

function degenerate(v: string): boolean {
  return DEGENERATE_VERSIONS.has(v.trim()) || /^0+(\.0+)*$/.test(v.trim()) || /^\d{10,}$/.test(v.trim());
}

export function runIdentity(ctx: AuditContext): void {
  const app = ctx.app;
  if (app === undefined) {
    ctx.collector.add({ id: "bundle.missing", group: G, status: "fail", detail: "No .app bundle was found for the audit target." });
    return;
  }

  if (app.escapes.length > 0) {
    ctx.collector.add({
      id: "bundle.escape",
      group: G,
      status: "fail",
      detail: `${app.escapes.length} path(s) in the bundle resolve outside the .app (or name a path outside it). shipcheck refused to read or execute them, so results that depend on them are incomplete.`,
      evidence: app.escapes.slice(0, 12).map((x) => `${x.kind}: ${x.rel} — ${x.detail}`),
      hint: "Remove symlinks that point outside the bundle and use a plain file name for CFBundleExecutable; a shippable .app is self-contained.",
      basis: "verified",
    });
  }

  if (!app.infoPlist.ok && app.infoPlist.toolUnavailable === true) {
    ctx.collector.add(unknown("bundle.info-plist", G, `Contents/Info.plist could not be read: ${app.infoPlist.error ?? "plutil unavailable"}. Identity, version and ASAR-integrity checks that depend on it did not run.`));
    return;
  } else if (!app.infoPlist.ok) {
    ctx.collector.add({
      id: "bundle.info-plist",
      group: G,
      status: "fail",
      detail: `Contents/Info.plist missing or unparseable (${app.infoPlist.error ?? "unknown"}). A launch blocker.`,
      hint: "Rebuild the bundle; every macOS app must ship a readable Info.plist.",
    });
  }

  const dict = app.infoPlist.dict;
  const bundleId = dict !== undefined ? getString(dict, "CFBundleIdentifier") : undefined;
  const shortVersion = dict !== undefined ? getString(dict, "CFBundleShortVersionString") : undefined;
  const buildVersion = dict !== undefined ? getString(dict, "CFBundleVersion") : undefined;
  const execName = dict !== undefined ? getString(dict, "CFBundleExecutable") : undefined;

  if (bundleId === undefined || bundleId.trim() === "") {
    ctx.collector.add({
      id: "bundle.identifier",
      group: G,
      status: "fail",
      detail: "CFBundleIdentifier missing — Gatekeeper, preferences and updaters all misbehave without it.",
    });
  } else if (!isReverseDns(bundleId)) {
    ctx.collector.add(warn("bundle.identifier-format", G, `CFBundleIdentifier is not reverse-DNS style: "${bundleId}".`, undefined, "Tooling (notarytool, app-specific updaters) assumes reverse-DNS ids."));
  } else {
    ctx.collector.add(info("bundle.identifier", G, `CFBundleIdentifier: ${bundleId}`));
  }

  const versionEvidence: string[] = [];
  let okVersion = true;
  if (shortVersion === undefined || shortVersion.trim() === "") {
    okVersion = false;
    ctx.collector.add({ id: "bundle.short-version", group: G, status: "fail", detail: "CFBundleShortVersionString missing — the app shows no usable version anywhere." });
  } else if (degenerate(shortVersion)) {
    okVersion = false;
    ctx.collector.add(warn("bundle.short-version-placeholder", G, `CFBundleShortVersionString="${shortVersion}" looks like an unreplaced placeholder.`, undefined, "Wire the real release version into the build."));
  } else {
    versionEvidence.push(`CFBundleShortVersionString=${shortVersion}`);
  }
  if (buildVersion === undefined || buildVersion.trim() === "") {
    okVersion = false;
    ctx.collector.add({ id: "bundle.build-version", group: G, status: "fail", detail: "CFBundleVersion missing — macOS treats build numbers as the machine-readable identity." });
  } else {
    versionEvidence.push(`CFBundleVersion=${buildVersion}`);
  }
  if (okVersion) {
    ctx.collector.add(passVersion(versionEvidence));
  }

  if (execName === undefined) {
    ctx.collector.add({ id: "bundle.executable-name", group: G, status: "fail", detail: "CFBundleExecutable missing." });
  } else if (app.execPath === undefined || !existsSync(app.execPath) || !statFileSync(app.execPath)) {
    ctx.collector.add({
      id: "bundle.executable-present",
      group: G,
      status: "fail",
      detail: app.execPath === undefined
        ? `CFBundleExecutable="${execName}" was refused (it or its location escapes the bundle; see bundle.escape) — executable-dependent checks did not run.`
        : `CFBundleExecutable="${execName}" but ${app.execPath} is not a file on disk — the app will not launch.`,
    });
  } else {
    ctx.collector.add(info("bundle.executable-present", G, `Main executable: Contents/MacOS/${execName}`));
  }

  const minSys = dict !== undefined ? getString(dict, "LSMinimumSystemVersion") : undefined;
  if (minSys === undefined) {
    ctx.collector.add(warn("bundle.minimum-system", G, "LSMinimumSystemVersion absent — users on older macOS crash on launch and your crash reports will look like product bugs.", undefined, "Declare the minimum deployment target."));
  } else {
    ctx.collector.add(info("bundle.minimum-system", G, `LSMinimumSystemVersion: ${minSys}`));
  }

  runHelperMetadata(ctx, app);
}

function statFileSync(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function isReverseDns(id: string): boolean {
  return /^[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)+$/.test(id);
}

function passVersion(evidence: string[]) {
  return { id: "bundle.version-fields", group: G, status: "pass" as const, detail: "Version fields present.", evidence };
}

function runHelperMetadata(ctx: AuditContext, app: AppStructure): void {
  if (app.helperApps.length === 0) return;
  const dict = app.infoPlist.dict;
  const mainShort = dict !== undefined ? getString(dict, "CFBundleShortVersionString") : undefined;
  const mainIdRoot = (dict !== undefined ? getString(dict, "CFBundleIdentifier") : undefined)?.split(".")[0];
  const problems: string[] = [];
  let helpersOK = 0;
  for (const helper of app.helperApps) {
    try {
      const helperInfo = readAppStructure(helper);
      const hdict = helperInfo.infoPlist.dict;
      const hshort = hdict !== undefined ? getString(hdict, "CFBundleShortVersionString") : undefined;
      if (helperInfo.infoPlist.ok === false) {
        problems.push(`${basename(helper)}: Info.plist unreadable`);
        continue;
      }
      if (mainShort !== undefined && hshort !== undefined && hshort !== mainShort) {
        problems.push(`${basename(helper)}: CFBundleShortVersionString=${hshort} ≠ main ${mainShort}`);
      }
      if (mainIdRoot !== undefined) {
        const hid = hdict !== undefined ? getString(hdict, "CFBundleIdentifier") : undefined;
        if (hid !== undefined && !hid.startsWith(mainIdRoot)) {
          problems.push(`${basename(helper)}: CFBundleIdentifier=${hid} does not share the main app's org`);
        }
      }
      helpersOK += 1;
    } catch {
      problems.push(`${basename(helper)}: unreadable`);
    }
  }
  if (problems.length > 0) {
    ctx.collector.add({
      id: "bundle.helper-metadata",
      group: G,
      status: "warn",
      detail: `Helper app metadata disagrees with the main bundle — sign of a stale or mixed build tree.`,
      evidence: problems.slice(0, 6),
      hint: "Rebuild the whole .app in one pass; never hand-swap helpers.",
    });
  } else {
    ctx.collector.add(info("bundle.helper-metadata", G, `${helpersOK} helper app(s); metadata consistent with the main bundle.`));
  }
}

export function runSignatures(ctx: AuditContext): void {
  const app = ctx.app;
  if (app === undefined) return;
  const params = ctx.params;

  const strict: VerifyResult = verifyStrict(app.bundlePath, false, params);
  const deep: VerifyResult = verifyStrict(app.bundlePath, true, params);
  const display: CodeInfo = parseDisplaySafe(app.bundlePath, params);
  ctx.bundleDisplay = display;
  const retry = "Re-run; if it persists raise --timeout-sec or check the host's Command Line Tools.";

  if (display.toolUnavailable !== undefined) {
    ctx.collector.add(unknown("sign.presence", S, `Could not tell whether the bundle is signed: ${display.toolUnavailable}.`, [display.toolUnavailable], retry));
  } else if (display.notSigned) {
    ctx.collector.add({
      id: "sign.presence",
      group: S,
      status: "fail",
      detail: "The bundle is not code-signed at all — Gatekeeper blocks install and users see “app is damaged” style blockers.",
      evidence: ["codesign: code object is not signed at all"],
      hint: "Sign with a Developer ID identity under hardened runtime, then notarize and staple.",
    });
    ctx.collector.add({ id: "sign.validity", group: S, status: "skip", detail: "Signature validity skipped: nothing signed." });
    checkCodeSignatureResources(ctx, app);
    return;
  }

  const adhocKind = classifyAdhoc(display, app.codeSignDir !== undefined);
  if (adhocKind === "linker-only") {
    reportLinkerOnlySignature(ctx, app, display, strict);
    return;
  }

  if (strict.toolUnavailable !== undefined) {
    ctx.collector.add(unknown("sign.validity", S, `Signature validity could not be determined: ${strict.toolUnavailable}. This is not evidence of a broken signature.`, [strict.toolUnavailable], retry));
  } else {
    ctx.collector.add(
      strict.ok
        ? { id: "sign.validity", group: S, status: "pass", detail: "codesign --verify --strict passes on the main bundle (integrity only; see sign.author for who signed it)." }
        : {
            id: "sign.validity",
            group: S,
            status: "fail",
            detail: "codesign --verify --strict fails on the main bundle — the signature is broken.",
            evidence: dedupe(strict.detail).slice(0, 6),
            hint: "Re-sign the whole .app (nested code first), then notarize and staple.",
          },
    );
  }

  if (deep.toolUnavailable !== undefined) {
    ctx.collector.add(unknown("sign.nested", S, `Nested code could not be verified: ${deep.toolUnavailable}. This is not evidence of broken nested signatures.`, [deep.toolUnavailable], retry));
  } else if (deep.ok) {
    ctx.collector.add({ id: "sign.nested", group: S, status: "pass", detail: "Nested code (helpers/frameworks) passes verification (--deep --strict)." });
  } else {
    ctx.collector.add({
      id: "sign.nested",
      group: S,
      status: "fail",
      detail: "Nested code fails strict verification — inside the bundle, signatures are stale or broken.",
      evidence: dedupe(deep.detail)
        .filter((l) => !l.includes("valid on disk") && !l.includes("Designated Requirement"))
        .slice(0, 8),
      hint: "Rebuild or re-sign nested code; a fresh main executable next to stale helpers fails exactly like this.",
    });
  }

  if (display.toolUnavailable !== undefined) {
    const why = [display.toolUnavailable];
    ctx.collector.add(unknown("sign.author", S, "Signer could not be determined.", why, retry));
    ctx.collector.add(unknown("sign.team", S, "Signing team could not be determined.", why, retry));
    ctx.collector.add(unknown("sign.timestamp", S, "Signing timestamp could not be determined.", why, retry));
    checkCodeSignatureResources(ctx, app);
    return;
  }

  if (adhocKind === "unknown") {
    ctx.collector.add(
      unknown(
        "sign.adhoc",
        S,
        "An adhoc signature flag is present, but codesign reported no sealed-resources verdict, so whether the .app bundle itself is ad-hoc signed or only its main executable carries a linker-generated signature could not be determined.",
        ["Signature=adhoc", "codesign -dv: no Sealed Resources line"],
        "Re-run the audit; if it persists, inspect the bundle with codesign -d --verbose=4 and look for a Contents/_CodeSignature directory.",
      ),
    );
  } else if (adhocKind === "bundle-adhoc") {
    ctx.collector.add(
      warn(
        "sign.adhoc",
        S,
        "Signature is ad-hoc. Fine for local runs; not suitable for general Developer ID distribution.",
        ["Signature=adhoc", "Sealed Resources present; Contents/_CodeSignature present"],
        "Sign with a paid Apple Developer “Developer ID Application” identity.",
      ),
    );
  } else if (display.authority.length > 0) {
    checkSigner(ctx, app.bundlePath, display);
  } else {
    ctx.collector.add(unknown("sign.author", S, "codesign reported no Authority chain — unexpected for a release signature.", ["stdout had no Authority="], "Re-run the audit on a fresh copy; if it persists, re-sign."));
  }

  const team = display.teamIdentifier;
  if (team === undefined || team === "" || team === "not set" || team.toLowerCase().includes("unavailable")) {
    ctx.collector.add({
      id: "sign.team",
      group: S,
      status: display.signatureAdhoc ? "warn" : "fail",
      detail: "No signing team identifier on the main bundle.",
      hint: "Releases must bind to a real Developer ID team for Gatekeeper, notarization and crash attribution.",
    });
  } else if (ctx.developerIdAnchored === true) {
    ctx.collector.add({ id: "sign.team", group: S, status: "pass", detail: `Signed by team ${team} (TeamIdentifier from a certificate codesign verified as Apple-issued Developer ID).`, basis: "verified" });
  } else {
    ctx.collector.add({
      id: "sign.team",
      group: S,
      status: "warn",
      detail: `TeamIdentifier ${team} comes from a certificate that is not proven to be an Apple-issued Developer ID, so it cannot be trusted for attribution.`,
      basis: "inferred",
    });
  }

  const stamp = display.timestamp;
  ctx.collector.add({
    id: "sign.timestamp",
    group: S,
    status: stamp !== undefined && stamp !== "" ? "pass" : "warn",
    detail:
      stamp !== undefined && stamp !== ""
        ? `Secure signing timestamp present (${stamp}); signature stays valid after certificates expire.`
        : "No secure signing timestamp observed; certificate expiry may affect validation.",
    hint: stamp !== undefined && stamp !== "" ? undefined : "codesign --timestamp (default for Developer ID signing).",
  });

  checkCodeSignatureResources(ctx, app);
}

/**
 * A .app whose main executable carries only the linker-generated ad-hoc
 * signature is an UNSIGNED bundle, not an ad-hoc-signed app. codesign -d on
 * such a bundle prints flags=(adhoc,linker-signed), `Info.plist=not bound`,
 * `Sealed Resources=none` and no Authority; there is no
 * Contents/_CodeSignature and --verify --strict fails. Reported as unsigned,
 * with the inner Mach-O signature named so no one reads it as bundle signing.
 */
function reportLinkerOnlySignature(ctx: AuditContext, app: AppStructure, display: CodeInfo, strict: VerifyResult): void {
  const flagLine = display.flagNames.length > 0 ? `flags=(${display.flagNames.join(",")})` : "flags not parsed";
  const sealLine = `codesign -dv: Sealed Resources=${display.sealedResources === false ? "none" : "not reported"}`;
  const codeSignLine = app.codeSignDir === undefined ? "Contents/_CodeSignature: absent" : "Contents/_CodeSignature: present";
  ctx.collector.add({
    id: "sign.presence",
    group: S,
    status: "fail",
    detail:
      "The .app bundle is not code-signed. Its main executable carries only a linker-generated ad-hoc signature, which does not sign the bundle — this is not an ad-hoc-signed app.",
    evidence: [
      `codesign -dv: ${flagLine}`,
      `codesign -dv: Signature=${display.signatureAdhoc ? "adhoc" : "none"}, TeamIdentifier=${display.teamIdentifier ?? "not set"}`,
      sealLine,
      codeSignLine,
    ],
    hint: "Sign the .app with a Developer ID Application identity under hardened runtime, then notarize and staple.",
    basis: "verified",
  });

  if (strict.toolUnavailable !== undefined) {
    ctx.collector.add(unknown("sign.validity", S, `Signature validity could not be determined: ${strict.toolUnavailable}. This is not evidence of a broken signature.`, [strict.toolUnavailable], "Re-run; if it persists raise --timeout-sec or check the host's Command Line Tools."));
  } else {
    ctx.collector.add(
      strict.ok
        ? { id: "sign.validity", group: S, status: "pass", detail: "codesign --verify --strict passes on the main bundle (integrity only; see sign.author for who signed it).", basis: "verified" }
        : {
            id: "sign.validity",
            group: S,
            status: "fail",
            detail: "codesign --verify --strict fails on the bundle, consistent with an unsigned bundle that has no sealed resources.",
            evidence: dedupe(strict.detail).slice(0, 6),
            hint: "Re-sign the whole .app (nested code first), then notarize and staple.",
            basis: "verified",
          },
    );
  }

  ctx.collector.add(
    warn(
      "sign.linker-signature",
      S,
      "The main executable carries a linker-generated ad-hoc signature only (linker-signed). This is the signature the toolchain emits on its own; it carries no identity and covers no bundle resources.",
      [`codesign -dv: ${flagLine}`, sealLine],
      "Do not present this as an ad-hoc-signed build; sign the bundle with a real identity before distribution.",
    ),
  );

  checkCodeSignatureResources(ctx, app);
}

/**
 * sign.author. `codesign --verify --strict` proves integrity, not trust, and
 * Authority= lines are just certificate display names. The only "pass" is
 * Developer ID Application whose chain codesign itself confirms against
 * Apple's Developer ID requirement.
 */
function checkSigner(ctx: AuditContext, bundlePath: string, display: CodeInfo): void {
  const chain = display.authority;
  const evidence = chain.slice(0, 3);
  const cls = classifyAuthority(chain);
  const anchoredName = chain[chain.length - 1] === "Apple Root CA";

  if (cls === "developer-id" && anchoredName) {
    const req = verifyDeveloperIdRequirement(bundlePath, ctx.params);
    if (req.toolUnavailable !== undefined) {
      ctx.collector.add(unknown("sign.author", S, `Signer trust could not be verified: ${req.toolUnavailable}.`, [req.toolUnavailable, ...evidence]));
      return;
    }
    if (req.satisfied) {
      ctx.developerIdAnchored = true;
      ctx.collector.add({ id: "sign.author", group: S, status: "pass", detail: "Signed with a Developer ID Application certificate anchored to Apple (codesign Developer ID requirement satisfied).", evidence, basis: "verified" });
      return;
    }
    ctx.collector.add({
      id: "sign.author",
      group: S,
      status: "fail",
      detail: "The signer's name says Developer ID Application, but codesign's Developer ID requirement is NOT satisfied — the certificate is not an Apple-issued Developer ID (a self-made certificate can carry any display name).",
      evidence: [...evidence, ...req.detail.slice(0, 2)],
      hint: "Re-sign with a Developer ID Application certificate issued through your Apple Developer account.",
      basis: "verified",
    });
    return;
  }
  if (cls === "apple-development" || cls === "app-store") {
    ctx.collector.add({
      id: "sign.author",
      group: S,
      status: "warn",
      detail:
        cls === "apple-development"
          ? "Signed with an Apple Development certificate — for local development only; not suitable for general Developer ID distribution."
          : "Signed with an App Store distribution certificate — not distributable outside the Mac App Store.",
      evidence,
      hint: "For direct distribution sign with a “Developer ID Application” certificate, then notarize and staple.",
      basis: "inferred",
    });
    return;
  }
  ctx.collector.add({
    id: "sign.author",
    group: S,
    status: "fail",
    detail:
      cls === "developer-id"
        ? "The signer claims Developer ID Application, but the certificate chain does not end in Apple Root CA — self-signed or forged name."
        : "The signing certificate is not a Developer ID Application certificate chained to Apple (self-signed or an unrecognized authority) — Gatekeeper will not accept it.",
    evidence,
    hint: "Sign with a “Developer ID Application” certificate issued through your Apple Developer account.",
    basis: "inferred",
  });
}

function checkCodeSignatureResources(ctx: AuditContext, app: AppStructure): void {
  if (app.codeSignDir !== undefined) {
    ctx.collector.add(info("sign.resources", S, "Contents/_CodeSignature present."));
  } else {
    ctx.collector.add({ id: "sign.resources", group: S, status: "fail", detail: "Contents/_CodeSignature missing — not a complete signed bundle." });
  }
}

function parseDisplaySafe(path: string, params: { timeoutMs: number }): CodeInfo {
  return displayInfo(path, params);
}

function dedupe(list: string[]): string[] {
  return [...new Set(list)];
}
