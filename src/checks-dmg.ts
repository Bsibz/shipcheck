// DMGs: non-mounting container metadata only. Never attach, unpack, run a
// license/installer, or traverse a filesystem from the image.
import { lstatSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import type { AuditContext } from "./checkscommon.js";
import { run } from "./checkscommon.js";
import { asDict, getString, parsePlistXml } from "./plist.js";

export function runDmgChecks(ctx: AuditContext): void {
  if (ctx.target.kind !== "dmg") return;
  const addUnknown = (detail: string): void => { ctx.collector.add({ id: "dmg.container", group: "disk image", status: "unknown", detail }); };
  try {
    const input = resolve(ctx.target.input);
    if (!lstatSync(input).isFile()) throw new Error("not regular");
    const path = realpathSync(input);
    const before = lstatSync(path);
    if (!before.isFile()) {
      addUnknown("DMG metadata requires a regular file; no image tool was invoked.");
    } else {
      const result = run(ctx, "dmg-info", [path], 1024);
      const after = lstatSync(path);
      const changed = before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs;
      if (changed) addUnknown("DMG identity changed during metadata inspection; no container facts are claimed.");
      else if (result.status !== "ok" || result.code !== 0) addUnknown(`Container metadata unavailable (${result.status}${result.status === "ok" ? `, exit ${result.code}` : ""}). Unsupported/encrypted images and host-tool errors do not establish a product defect.`);
      else {
        const parsed = parsePlistXml(result.stdout);
        const dict = parsed.ok ? asDict(parsed.value) : undefined;
        const format = getString(dict, "Format");
        if (format === undefined) addUnknown("Host output did not contain a recognized image format; container metadata remains unknown.");
        else ctx.collector.add({ id: "dmg.container", group: "disk image", status: "info", basis: "verified", detail: "Container metadata observed by the non-mounting imageinfo tool; this is not image checksum verification or payload validation.", evidence: [`Format=${format.slice(0, 160)}`, `File bytes=${before.size}`] });
      }
    }
  } catch { addUnknown("Container metadata could not be inspected safely; raw image/tool diagnostics are not printed."); }
  ctx.collector.add({ id: "dmg.payload", group: "disk image", status: "unknown", detail: "DMG was not mounted or extracted. Bundle identity, architectures, signatures, entitlements, notarization, Gatekeeper and native/updater payload checks are UNKNOWN. Audit a separately supplied .app or release ZIP for those checks." });
}
