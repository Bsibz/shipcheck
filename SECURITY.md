# Security policy

ShipCheck parses untrusted release artifacts (bundles, ZIPs, DMG containers, ASAR archives, Mach-O headers, plist/YAML/XML metadata) and runs a fixed set of Apple host tools on them, so parser and confinement bugs matter.

## Supported versions

No version has been published yet. Once released, only the latest `0.x` release will receive fixes.

## Reporting a vulnerability

The public repository now exists, but a private vulnerability-reporting channel has not been configured yet. Do not put exploitable details, proprietary apps, credentials, or secrets in a public issue. A verified private reporting path will be documented here before the first tagged/package release.

This is a small project and no response-time guarantee is made.

## In scope

- Code execution, or any launch, of the inspected artifact.
- Writes outside the chosen output paths or the tool's disposable scratch directory (ZIP traversal, symlink/hardlink tricks, overwrite-protection bypass).
- Injection through crafted artifact content into HTML, Markdown, or terminal output.
- Unbounded resource use from small crafted inputs beyond the documented limits.
- Leaking updater feed URLs, tokens, or keys that are documented as redacted.

## Out of scope

- A clean report is not a security guarantee about the inspected app; ShipCheck is a preflight, not a malware scanner.
- Hostile concurrent modification of an artifact during inspection (documented as unsupported).
- Behavior of Apple host tools (`codesign`, `otool`, `hdiutil`, ...) themselves.
