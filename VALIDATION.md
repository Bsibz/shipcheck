# Validation

What has and has not been checked for the 0.2.0 release. Evidence is stated as executed, not implied.

## Gates (executed)

- `npm ci && npm test`: TypeScript strict build plus the full `node --test` suite (96 tests, 0 failures, 0 skipped) on macOS arm64, under both Node 22.23.0 and Node 24.16.0 (local runs). Coverage includes synthetic healthy/broken ASAR, ZIP confinement and CRC, output overwrite protection, binary plists, fixed host-tool routes, signer classification, timeout and unknown handling, HTML injection, native load-command resolution, updater metadata limits and redaction, the non-mounting DMG route, strict-mode exits, and repository hygiene (no private paths in tracked files).
- `npm run ci:strict-smoke`: the built CLI against throwaway fixtures. Unreadable DMG: default exit 0, `--strict` exit 6, `--strict --fail-on never` exit 3. Unsigned skeleton app: exit 2 with and without `--strict` (failures outrank unresolved findings).
- `npm run release:check`: `package.json`, `package-lock.json`, `dist/cli.js --version`, and `CHANGELOG.md` agree on 0.2.0; the `npm pack --dry-run` tarball contains only `dist`, `samples`, and top-level docs and has no private machine paths.
- GitHub Actions (`.github/workflows/ci.yml`, macOS, Node 22 and 24) runs the same three commands. It has not run on a hosted runner; the same commands were run locally under Node 22 and 24. Check the first hosted run before tagging.

## Packed install (executed locally)

`npm pack` output installed into an isolated `--prefix` outside this tree: both `shipcheck` and `shipcheck-mac` reported `0.2.0` and audited a synthetic bundle. Nothing has been published to npm or any Git host.

## Real-world exposure

- One real Electron app, audited as an installed bundle on one Apple-silicon Mac, plus one real DMG container (metadata only). No other third-party apps, Intel Macs, or older macOS releases have been exercised. Those receipts are private and are not included here.
- No inspected app was ever launched, mounted, installed, signed, or notarized by ShipCheck.

## Known limits

- Static analysis cannot prove Electron ABI compatibility, runtime dynamic loading, working update delivery, malware absence, clean-Mac launch, notarization acceptance, or a successful customer install.
- Native dependency resolution is bounded (600 images, 1 MiB tool output per image); intermediate-loader runpaths and dynamic loading are not modeled. Some `otool` path interpretations fail on helper names ending in parentheses, which stays UNKNOWN rather than a finding.
- Updater coverage is field inspection of local sidecar files only: no feed fetch, artifact association, signature verification, or publisher trust.
- DMGs get container metadata only; payload checks need a separate `.app` or ZIP.
- Bundle snapshots are not atomic; do not mutate an artifact during inspection. ZIP identity changes are detected by inode/size/mtime; an adversary who preserves metadata is out of scope.
- Host tools run unsandboxed with a minimal environment. There is no lint script configured.
- Node 22 and 24 are the tested runtimes; older Node versions are unsupported.
