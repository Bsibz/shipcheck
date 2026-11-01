# Security policy

ShipCheck parses untrusted release artifacts (bundles, ZIPs, DMG containers, ASAR archives, Mach-O headers, plist/YAML/XML metadata) and runs a fixed set of Apple host tools on them, so parser and confinement bugs matter.

## Supported versions

Only the latest `0.x` release receives fixes.

## Reporting a vulnerability

Report privately through GitHub: open <https://github.com/Bsibz/shipcheck/security/advisories/new> (the repository's **Security** tab, **Report a vulnerability**). Do not put exploitable details, proprietary apps, credentials, or secrets in a public issue; if you cannot use the private form, open a public issue that asks for a private contact without including any details.

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
