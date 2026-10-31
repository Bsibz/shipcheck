# Contributing

Bug reports with a sanitized receipt (or a minimal synthetic fixture) are the most useful contribution.

```sh
npm ci
npm test                  # build + full test suite
npm run ci:strict-smoke   # --strict exit-code proof
npm run release:check     # only meaningful when preparing a release
```

Ground rules:

- ShipCheck stays read-only and offline by default. It must never execute, mount, modify, or upload an inspected artifact. Network-capable checks must stay opt-in flags.
- Unknown is better than guessed: if evidence is insufficient, record UNKNOWN, not a pass.
- Fixtures must be synthetic or sanitized. Do not commit real apps, receipts, signing identities, team IDs, or home-directory paths (use `/Users/demo/...`-style placeholders). `npm run release:check` scans the tarball for private paths.
- Add or update tests for behavior changes, and an entry under the next version in CHANGELOG.md.
