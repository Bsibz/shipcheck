// Streamed helpers around release artifacts.

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { statSync } from "node:fs";

export async function sha256File(path: string): Promise<string | undefined> {
  try {
    statSync(path);
  } catch {
    return undefined;
  }
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const stream = createReadStream(path, { highWaterMark: 1024 * 1024 });
    stream.on("data", (chunk: string | Buffer) => h.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(h.digest("hex")));
  });
}

export function sha256Text(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}
