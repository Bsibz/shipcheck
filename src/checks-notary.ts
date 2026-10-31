// Notarization and Gatekeeper checks.
//
// Facts on macOS 27 (captured live):
//   - codesign -d --verbose=4 prints `Notarization Ticket=stapled` on stapled
//     apps, and NO notarization line otherwise.
//   - spctl -a -vv -t exec: accepted (exit 0, source/origin lines) or rejected
//     (exit 3 "rejected").
//   - stapler validate: exit 0 "The validate action worked!" / 65 "does not
//     have a ticket stapled to it." / 64 usage. NOTE: this downloads a ticket
//     when it can — so it runs only with --stapler.
//   - xattr -p com.apple.quarantine: exit 0 with value, or exit 1 "No such
//     xattr".

import type { AuditContext } from "./checkscommon.js";
import { GROUP, fail, unknown, warn } from "./checkscommon.js";
import { quarantineState, spctlAssess, staplerValidate } from "./gatekeeper.js";
import { displayInfo } from "./codesign.js";

const N = GROUP.notarization;
const GK = GROUP.gatekeeper;

export function runNotarization(ctx: AuditContext): void {
  const app = ctx.app;
  if (app === undefined) return;
  // The ticket lives with the bundle, so read the bundle-level codesign facts
  // (already gathered by runSignatures) rather than the inner executable's.
  const display = ctx.bundleDisplay ?? displayInfo(app.bundlePath, ctx.params);

  const stapled = display.notarizationStapled;
  if (ctx.opts.stapler) {
    const st = staplerValidate(app.bundlePath, ctx.params);
    if (st.validated) {
      ctx.collector.add({
        id: "not.stapler",
        group: N,
        status: "pass",
        detail: "stapler validate: ticket attached and valid.",
        evidence: [st.note],
      });
    } else if (st.exitCode === 65) {
      ctx.collector.add({
        id: "not.stapler",
        group: N,
        status: "fail",
        detail: "stapler validate: no notarization ticket stapled to the bundle.",
        evidence: [st.note],
        hint: "xcrun notarytool submit, then xcrun stapler staple MyApp.app.",
      });
    } else {
      ctx.collector.add(unknown("not.stapler", N, `stapler validate failed with exit ${st.exitCode}.`, [st.note]));
    }
  }

  if (display.toolUnavailable !== undefined) {
    ctx.collector.add(unknown("not.stapled", N, `Stapling could not be determined: ${display.toolUnavailable}.`, [display.toolUnavailable]));
  } else if (stapled) {
    ctx.collector.add({
      id: "not.stapled",
      group: N,
      status: "pass",
      detail: ctx.opts.stapler
        ? "codesign reports a stapled notarization ticket on the bundle (see not.stapler for validation)."
        : "codesign reports a stapled notarization ticket on the bundle: a ticket is present, but its validity and revocation status are unverified without --stapler.",
    });
  } else {
    ctx.collector.add(
      warn(
        "not.stapled",
        N,
        "No stapled ticket observed locally. Offline launch acceptance is unproven; assess a clean customer Mac.",
        ["codesign -dv: no Notarization Ticket line"],
        "Notarize and staple: xcrun notarytool submit → xcrun stapler staple.",
      ),
    );
  }
}

export function runGatekeeperChecks(ctx: AuditContext): void {
  const app = ctx.app;
  if (app === undefined) return;

  if (!ctx.opts.gatekeeper) {
    // spctl may consult Apple's services, so it never runs unless asked.
    ctx.collector.add(
      unknown(
        "gatekeeper.assess",
        GK,
        "Gatekeeper assessment not run: spctl may contact Apple, and shipcheck is offline by default. Result is UNKNOWN, not a pass.",
        undefined,
        "Re-run with --gatekeeper to opt in (may contact Apple).",
      ),
    );
  } else {
    runSpctl(ctx, app.bundlePath);
  }

  const quar = quarantineState(app.bundlePath, ctx.params);
  ctx.collector.add({
    id: "gatekeeper.quarantine",
    group: GK,
    status: quar.error !== undefined ? "unknown" : "info",
    detail:
      quar.error !== undefined
        ? "Quarantine state could not be read."
        : quar.quarantined
          ? "com.apple.quarantine xattr present (typical for downloads)."
          : "No quarantine xattr (typical for locally-installed or adopted apps).",
    evidence: quar.error !== undefined ? [quar.error] : quar.quarantined ? [`value: ${quar.value ?? "(unparsed)"}`] : undefined,
  });
}

function runSpctl(ctx: AuditContext, bundlePath: string): void {
  const sp = spctlAssess(bundlePath, ctx.params);
  if (sp.assessment === "accepted") {
    ctx.collector.add({
      id: "gatekeeper.assess",
      group: GK,
      status: "pass",
      detail: `Gatekeeper assessment: accepted (${sp.source ?? "policy"}).`,
      evidence: [sp.source !== undefined ? `source=${sp.source}` : undefined, sp.origin !== undefined ? `origin=${sp.origin}` : undefined].filter((x): x is string => x !== undefined),
    });
  } else if (sp.assessment === "rejected") {
    const quar = quarantineState(bundlePath, ctx.params);
    ctx.collector.add({
      id: "gatekeeper.assess",
      group: GK,
      status: "fail",
      detail: quar.quarantined
        ? "Gatekeeper rejects the app AND it carries a quarantine flag — a user who downloads this cannot launch it without overrides."
        : "Gatekeeper rejects the app. On customer machines this blocks launch unless they bypass protections (which you cannot rely on).",
      evidence: [sp.note ?? "spctl: rejected"],
      hint: "Renotarize or fix signing defects, then staple.",
    });
  } else {
    ctx.collector.add(
      unknown(
        "gatekeeper.assess",
        GK,
        sp.override !== undefined ? `spctl said accepted but reported override=${sp.override}; Gatekeeper is not being enforced on this host, so there is no real verdict.` : `spctl produced no verdict (exit ${sp.exitCode}).`,
        [sp.note ?? ""],
        sp.override !== undefined ? "Re-run on a host with Gatekeeper assessments enabled (spctl --status)." : undefined,
      ),
    );
  }
}
