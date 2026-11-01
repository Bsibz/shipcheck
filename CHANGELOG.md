# Changelog

All notable changes are recorded here. Versions follow [semver](https://semver.org/); while the major version is 0, minor releases may change report fields, finding IDs and flags.

## [0.2.0] - 2026-11-01

First public release. Earlier internal milestones (0.1.0, 0.2.0-rc.0) were never published.

### Added
- Read-only audit of `.app` bundles, release ZIPs, and DMG containers with text, JSON, Markdown, and standalone HTML reports.
- Checks: bundle identity, code signature and signer classification, hardened runtime and entitlements, local notarization/stapling evidence, opt-in Gatekeeper (`--gatekeeper`) and stapler (`--stapler`), architectures, ASAR header/inventory/integrity, bounded native load-command inspection, executable and resource SHA-256 fingerprints, build-host path leaks.
- Local updater metadata inspection (`latest-mac.yml`, Sparkle appcast) with redaction; field shapes only, no feed fetch or signature verification.
- DMG container metadata via a fixed, non-mounting `hdiutil imageinfo` route.
- Evidence classes (VERIFIED / INFERRED / UNKNOWN); unknown and skipped checks are reported as unresolved, never as passes.
- `--strict`: exit 6 when recorded UNKNOWN/skipped findings remain, after failure (2) and warning (1) precedence; rejected with `--fail-on never` (exit 3).
- macOS GitHub Actions workflow (Node 22 and 24, green on hosted runners): build, tests, strict-mode exit-code smoke test, and a release-readiness check.
- `npm run release:check`: verifies `package.json`, lockfile, `dist/cli.js --version`, this changelog, an optional git tag, and the npm tarball contents agree and carry no private paths.

### Notes
- npm package name is `shipcheck-mac` (the `shipcheck` name belongs to an unrelated project); the installed commands are `shipcheck` and `shipcheck-mac`.
- Requires Node.js 22 or newer.
- Validation covers synthetic fixtures and one real Electron app on one Apple-silicon Mac. See VALIDATION.md.
