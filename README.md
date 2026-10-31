# ShipCheck

A local, read-only release artifact audit for macOS and Electron teams. Inspect a `.app`, release ZIP, or DMG container and turn evidence into a terminal verdict, JSON receipt, or standalone HTML report.

ShipCheck is a preflight, not a launch test or release certificate. It never launches the inspected application. A clean report means no warning or failure was detected within the selected checks. Unknown and skipped checks are still unresolved, and they are not passes.

**Status: 0.2.0, prepared for a first public release. Not yet published to npm or any public Git host.** The 0.x line follows semver's "anything may change" rule: report JSON fields, finding IDs and flags can still change between minor versions, so pin an exact version in CI. Validation so far is on synthetic fixtures and one real Electron app on one Apple-silicon Mac (see [VALIDATION.md](VALIDATION.md)); expect rough edges on bundle layouts we have not seen, and please file them.

## Install

Requires macOS, Node.js 22 or newer (CI expectation: Node 22 and 24 on macOS), and Apple's standard command-line inspection tools (`codesign`, `lipo`, `otool`, `xattr`, `file`, `hdiutil`). No runtime npm dependencies.

The npm package is `shipcheck-mac`; it provides both the `shipcheck` and `shipcheck-mac` commands. (`shipcheck` on npm belongs to an unrelated project, so this package uses a different name. If both are installed globally, use `shipcheck-mac` to disambiguate.)

### From a packed artifact (works today)

```sh
npm ci && npm pack                                  # creates shipcheck-mac-0.2.0.tgz
npm install --prefix ~/shipcheck-prefix ./shipcheck-mac-0.2.0.tgz
~/shipcheck-prefix/node_modules/.bin/shipcheck --version
```

### From npm (only after the first publication; not yet available)

```sh
npm install -g shipcheck-mac
npx shipcheck-mac /Applications/Example.app
```

### Planned locations (future, unpublished)

A public source repository and issue tracker are planned but do not exist yet. No URL is claimed here; this section will be updated when they do.

### From a source checkout

```sh
npm ci          # installs dev dependencies and compiles dist/cli.js
npm test
node dist/cli.js --version
```

## Use

```sh
shipcheck /Applications/Example.app
shipcheck /Applications/Example.app --format text --json receipt.json --html report.html
shipcheck ~/Downloads/Example-mac.zip --format json --out receipt.json
shipcheck /Applications/Example.app --asar-depth files --hashes all
shipcheck release/Example.app --update-metadata release/latest-mac.yml
shipcheck release/Example.app --update-metadata release/appcast.xml
shipcheck release/Example.dmg --format json
shipcheck --help
```

CI gate example (fails the job on warnings and on any unresolved check):

```sh
shipcheck build/Example.app --format json --out receipt.json --fail-on warn --strict
```

Exit codes are documented under [CI exit codes](#ci-exit-codes). The included GitHub Actions workflow is `.github/workflows/ci.yml`; it has not run on a hosted runner yet.

## Reports

JSON is the receipt. It carries the verdict (`clean`, `warnings`, or `failures`), each finding's status, and an evidence class (`verified`, `inferred`, or `unknown`). Text, Markdown, and HTML are renderings of that same receipt. They do not add a certification. HTML phrases such as "Not ready to ship" are display copy for the verdict enum.

`--format` chooses stdout. `--out` writes that same format. `--json` and `--html` can write the other renderings from the same run. One command, one audit.

`clean` and exit code 0 mean no warning or failure under the selected policy. Unknown and skipped checks can still be present. Text prints `UNRESOLVED` on the line after `VERDICT`. Markdown uses a purple mark for that case and keeps the green mark for a clean receipt with nothing unresolved. HTML uses the purple "coverage incomplete" verdict. Exit code 0 is not authority to ship.

Core inspection needs no upload, credentials, or network service. `--gatekeeper` opts into spctl assessment and `--stapler` opts into ticket validation; either may contact Apple. By default Gatekeeper remains UNKNOWN. Local Gatekeeper observations reflect this machine's policy and cache; they cannot certify a fresh customer Mac.

## Evidence and coverage

- Bundle ID, name, version/build, minimum OS and executable identity.
- Main/helper/native architectures, code signature verification, authority/team, hardened runtime and embedded entitlements.
- Local notarization/stapling evidence and Gatekeeper assessment where available.
- ASAR header/inventory and declared integrity records; optional per-file verification.
- Bounded native load-command inspection: main/helper executables, frameworks, native extensions and files with execute bits; missing path candidates and deployment-target declarations.
- Executable/resource SHA-256 fingerprints, visible updater metadata, build-host paths and provenance inconsistencies.

**VERIFIED** means observed by a local read or system tool, within its stated scope. **INFERRED** means a heuristic interpretation. **UNKNOWN** means evidence was insufficient. A valid signature alone does not prove Developer ID distribution, notarization, runtime correctness, updater delivery, or buyer readiness.

Native dependency resolution is static and incomplete (600 images, 1 MiB tool output per image): intermediate-loader runpaths, actual loading process, dynamic loading, target-file architecture, Electron ABI compatibility, and hardware behavior require separate runtime tests. Per-slice paths are kept separate; unlabelled thin-file architecture remains uncertain. Non-Mach-O/unreadable native payloads and capped/failed tool reads stay UNKNOWN. Presence is a candidate, never a successful load. An updater file proves its presence, not a working feed. Metadata and provenance labels are declarations unless corroborated.

## Local updater metadata and DMG limits

`--update-metadata FILE` inspects up to eight explicit local sidecars (256 KiB each). Conventional latest-mac.yml block fields cover version, files/URL, SHA-512 digest shape and positive size; legacy path/sha512 is recognized too. Appcast inspection covers ordinary RSS items/enclosures using the conventional Sparkle namespace, item-level or legacy enclosure versions, URL, length and EdDSA signature shape. Resources/latest-mac.yml and Resources/appcast.xml are also discovered locally. Feed URLs, tokens, keys and metadata values are redacted; metadata filenames and the SHA-256 of the bytes read are included.

These are field observations (INFERRED), not full YAML/XML validation. Alternate layouts, DTD/entities, CDATA, files over the cap and unreadable/symlinked metadata remain UNKNOWN. No artifact hash comparison, version matching to the input app, manifest/EdDSA signature verification, key trust, publisher binding or feed fetch is performed. Signatures and digests can have the expected shape and still be wrong. Squirrel/config/feed presence is a hint; absence does not prove updates are broken. Delivery stays UNKNOWN. Field shapes are based on [electron-builder metadata](https://www.electron.build/v26/docs/features/auto-update/) and [Sparkle appcasts](https://sparkle-project.org/documentation/publishing/).

DMGs receive **container metadata only** through a fixed local `/usr/bin/hdiutil imageinfo -plist -stdinpass` route. Only one absolute regular-file argument is accepted; source symlinks/devices/URLs are refused, and file identity is checked around the tool call. No attach/mount, extraction, checksum verification or image hash is performed. Bundle signatures, notarization, architectures and payload correctness stay UNKNOWN; supply a separate .app or ZIP to inspect those. Encrypted, unsupported, unreadable or failed-tool results remain UNKNOWN. No fresh-Mac DMG install/launch proof is claimed. Host tools run outside an OS sandbox; inspection is non-atomic and does not defend against hostile concurrent rewrites preserving file identity.

## CI exit codes

| Exit | Meaning |
| --- | --- |
| 0 | No warning or failure under the selected policy. Unknown and skipped checks can still be present. |
| 1 | Warnings |
| 2 | Failures, or warnings with `--fail-on warn` |
| 3 | Invalid usage/input |
| 4 | Unsupported environment/missing required tools |
| 5 | Output/internal error |
| 6 | Recorded UNKNOWN/skipped findings remain under `--strict` |

Use `--strict` for CI that must reject every recorded UNKNOWN/skipped finding. Failures and warnings retain exits 2/1 (warnings become 2 with `--fail-on warn`); otherwise unresolved findings exit 6. Default behavior and human-readable verdicts are unchanged. Strict mode counts all recorded gaps, including offline Gatekeeper, updater delivery, and container-only DMG payload coverage, so zero may be unattainable within a static audit. It does not prove unrecorded checks or runtime behavior. `--strict --fail-on never` is rejected with usage exit 3.

`--fail-on never` suppresses finding-based failure exits for report collection; usage/environment/output errors still matter. Preserve the receipt and inspect coverage, rather than treating exit zero as shipping authority.

```sh
shipcheck build/Example.app --format json --out receipt.json --fail-on warn
```

Example job for your own app repository (macOS runner required; works once `shipcheck-mac@0.2.0` is published to npm, which has not happened yet):

```yaml
- run: npx --yes shipcheck-mac@0.2.0 build/Example.app --format json --out receipt.json --fail-on warn --strict
```

## Security and privacy

Inspected app code is never executed. Artifact contents are treated as untrusted. ZIPs are handled in disposable local scratch space; the source archive remains unchanged. Output files must be new: existing destinations are refused by default to protect artifacts and prior evidence. `--force` permits replacing an ordinary report file; artifact paths, symlinks and hard links remain protected. Use a fresh filename for each run.

Reports can contain local paths, signing identity, identifiers and hashes. Review and sanitize receipts before sharing them. ShipCheck does not collect credentials or print updater configuration contents.

No signature, quarantine, entitlement, trust setting or inspected file is intentionally changed. Never select an output destination inside the inspected app or over the input ZIP.

## Tests and demo

```sh
npm test
node --test test/acceptance.test.mjs
npm run ci:strict-smoke   # exit-code proof for --strict against the built CLI
npm run release:check     # version/lockfile/changelog/tarball consistency
npm run samples
```

`samples/sample-report.html` and its text, JSON, and Markdown companions are the CLI's output on a generated, unsigned `Demo.app` fixture. Paths and the host label are normalized. Regenerate them with `npm run samples`. Synthetic failures demonstrate report behavior and are not claims about any shipping product. All fixtures in this repository are synthetic.

## Scope

ShipCheck supplies repeatable evidence for a release review. It does not sign, notarize, staple, or rebuild anything, and it does not certify App Store acceptance or customer launch success.

## Optional: done-for-you Ship Check

If you would rather have a person run this against one release build and hand back a prioritized fix list, a fixed-scope **Mac/Electron Ship Check** is planned at US$300 (no signing, notarizing, stapling, or rebuilding included). It is optional, the CLI is fully usable without it, and it is not yet offered publicly.

## License

[MIT](LICENSE). See [SECURITY.md](SECURITY.md) to report a vulnerability and [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.
