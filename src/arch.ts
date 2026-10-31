// CPU architecture facts for Mach-O targets via lipo (preferred) and file
// (fallback). Captured output shapes on macOS 27:
//   thin:   "Non-fat file: <path> is architecture: arm64"
//   fat:    "Architectures in the fat file: <path> are: x86_64 arm64 "
//   (older lipo may print "The architecture\nof <path>: x86_64 arm64")
//
// The token-based approach below is deliberately simple: every whitespace-
// separated token in lipo output is tested as an arch name; paths never match
// because they contain "/" or "." segments. Deterministic on real outputs.

export const ARCH_TOKEN_RE = /^(x86_64h?|arm64e?(\.\w+)?|i386|i686|ppc(64)?(740)?|armv6[km]?)$/i;

export interface ArchResult {
  archs: string[];
  universal: boolean;
  source: "lipo" | "file" | "none";
}

export function parseLipoInfo(stdout: string): string[] {
  const archs: string[] = [];
  for (const token of stdout.split(/\s+/)) {
    if (ARCH_TOKEN_RE.test(token) && !archs.includes(token.toLowerCase())) {
      archs.push(token.toLowerCase());
    }
  }
  // canonical order
  return archs.sort((a, b) => archPriority(a) - archPriority(b));
}

function archPriority(a: string): number {
  if (a.startsWith("x86")) return 0;
  if (a.startsWith("arm")) return 1;
  return 2;
}

export function parseFileArchOutput(fileLine: string): string[] {
  const found: string[] = [];
  const push = (t: string): void => {
    const lower = t.toLowerCase();
    if (ARCH_TOKEN_RE.test(lower) && !found.includes(lower)) found.push(lower);
  };

  // universal compact: "[x86_64:Mach-O 64-bit executable x86_64] [arm64:Mach-O ...]"
  for (const m of fileLine.matchAll(/\[([A-Za-z0-9_.]+):/g)) push(m[1] ?? "");
  // multi-line universal: "... executable x86_64] [arm64]" and
  // "/path (for architecture x86_64): Mach-O 64-bit executable x86_64"
  for (const m of fileLine.matchAll(/\[([A-Za-z0-9_.]+)\]/g)) push(m[1] ?? "");
  for (const m of fileLine.matchAll(/for architecture ([A-Za-z0-9_.]+)\)/g)) push(m[1] ?? "");

  if (found.length > 1) {
    return found.sort((a, b) => archPriority(a) - archPriority(b));
  }

  // thin: "... Mach-O 64-bit executable arm64" (or "bundle") — possibly "arm64]?"
  const m = fileLine.match(/(?:executable|bundle|library|stub|object)\s+(x86_64h?|arm64e?(?:\.\w+)?|i386)\]?$/i);
  if (m !== null && m[1] !== undefined) {
    return [m[1].toLowerCase()];
  }
  return found;
}
