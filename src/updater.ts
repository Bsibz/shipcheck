// Update-story detection. Generic, Electron-era names only; never report
// feed URLs or keys, just which local artifacts exist.

import { lstatSync } from "node:fs";
import { join } from "node:path";
import { containedRealPath, type AppStructure } from "./bundle.js";

export interface UpdaterFacts {
  appUpdateYml?: { path: string; size: number };
  latestMacYml?: { path: string; size: number };
  appcastXml?: { path: string; size: number };
  squirrelFramework?: string;
  electronUpdateHelper?: string;
  detected: string[];
}

const UPDATE_FILE_NAMES = new Set(["app-update.yml", "latest-mac.yml", "appcast.xml"]);

export function detectUpdater(app: AppStructure): UpdaterFacts {
  const facts: UpdaterFacts = { detected: [] };
  const resources = app.resourcesDir;
  if (resources !== undefined && app.bundleReal !== undefined && containedRealPath(app.bundleReal, resources) !== undefined) {
    for (const name of UPDATE_FILE_NAMES) {
      const p = join(resources, name);
      // lstat: a symlinked update file is never stat'ed through to its target.
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isFile()) {
        const entry = { path: p, size: st.size };
        if (name === "app-update.yml") facts.appUpdateYml = entry;
        if (name === "latest-mac.yml") facts.latestMacYml = entry;
        if (name === "appcast.xml") facts.appcastXml = entry;
        facts.detected.push(name);
      }
    }
  }
  for (const fw of app.frameworks) {
    if (basenameish(fw).includes("Squirrel")) {
      facts.squirrelFramework = fw;
      facts.detected.push("Squirrel.framework");
    }
  }
  for (const helper of app.helperApps) {
    if (basenameish(helper).includes("ShipIt") || basenameish(helper).includes("UpdateHelper")) {
      facts.electronUpdateHelper = helper;
      facts.detected.push("update helper app");
    }
  }
  return facts;
}

function basenameish(p: string): string {
  return p.split("/").pop() ?? p;
}
