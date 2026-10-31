// Local update evidence only. No feed fetch, updater run or delivery claim.
import { resolve } from "node:path";
import type { AuditContext } from "./checkscommon.js";
import { GROUP } from "./checkscommon.js";
import { containedRealPath } from "./bundle.js";
import { detectUpdater } from "./updater.js";
import { inspectUpdateMetadata } from "./update-metadata.js";

const U = GROUP.updater;
export function runUpdaterChecks(ctx: AuditContext): void {
  const app = ctx.app;
  const paths = [...(ctx.opts.updateMetadata ?? [])];
  if (app !== undefined) {
    const facts = detectUpdater(app);
    ctx.collector.add({
      id: "updater.story", group: U, status: "info", basis: "inferred",
      detail: facts.detected.length > 0
        ? `Local updater hints: ${facts.detected.join(", ")}. Presence does not prove an active updater or working delivery.`
        : "No updater hints observed in the inspected bundle. Custom code, remote feeds and manual delivery are not established by file absence.",
    });
    for (const entry of [facts.latestMacYml, facts.appcastXml]) {
      if (entry && app.bundleReal && containedRealPath(app.bundleReal, entry.path)) paths.push(entry.path);
    }
    const feed = app.infoPlist.dict?.SUFeedURL;
    if (typeof feed === "string") {
      let secure = false;
      try { const u = new URL(feed); secure = u.protocol === "https:" && !u.username && !u.password; } catch { /* redacted */ }
      ctx.collector.add({ id: "updater.sparkle-feed", group: U, status: secure ? "info" : "warn", basis: "inferred", detail: `SUFeedURL declared (${secure ? "HTTPS without embedded credentials" : "insecure or unsupported URL"}); value redacted. Feed reachability and updater activity are unknown.` });
    }
  }
  const unique = [...new Set(paths.map((p) => resolve(p)))].slice(0, 8);
  for (const path of unique) {
    const facts = inspectUpdateMetadata(path);
    ctx.collector.add({
      id: "updater.metadata", group: U,
      status: facts.unknown ? "unknown" : facts.problems.length > 0 ? "warn" : "info",
      basis: facts.unknown ? "unknown" : "inferred",
      detail: facts.unknown ?? (facts.problems.length > 0
        ? `Local ${facts.kind} metadata: ${facts.problems.join("; ")}. Field inspection only.`
        : `Local ${facts.kind} metadata: expected fields observed for ${facts.entries} release entry/enclosure(s). Syntax, artifact association and cryptographic validity are not established.`),
      evidence: [`file=${facts.name}; values/URLs redacted`, ...(facts.sha256 ? [`metadata SHA-256=${facts.sha256}`] : [])],
    });
  }
  if (paths.length > 8) ctx.collector.add({ id: "updater.coverage", group: U, status: "unknown", detail: "Updater metadata inspection capped at eight files; remaining files were not read." });
  if (app || unique.length > 0) ctx.collector.add({ id: "updater.delivery", group: U, status: "unknown", detail: "No update check, download, signature verification, install, feed access or end-to-end update rehearsal was performed." });
}
