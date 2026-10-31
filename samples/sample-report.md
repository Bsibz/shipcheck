# shipcheck report 🔴

- **Target:** `/Users/demo/Downloads/Demo.app` (bundle)
- **Bundle:** Demo.app
- **Verdict:** failures · unknown=3 skip=2 (not passes)
- **Artifact:** bundle · network: offline
- **Evidence:** 10 verified · 4 inferred · 5 unknown
- **When:** 2026-10-30T07:11:33.830Z
- **Tool:** shipcheck 0.2.0 · macOS Darwin (sanitized demo host) · arm64

> network: shipcheck has no network client; spctl and stapler were not run. Other host tools (codesign, xattr, lipo, otool, file) were invoked locally and are not sandboxed, so offline operation is by design, not OS-enforced.
> gatekeeper: spctl was not run (opt-in via --gatekeeper); the Gatekeeper verdict is UNKNOWN.

## bundle identity (4)

### ℹ️ info `bundle.identifier`

CFBundleIdentifier: com.example.demo

### ❌ fail `bundle.build-version`

CFBundleVersion missing — macOS treats build numbers as the machine-readable identity.

### ℹ️ info `bundle.executable-present`

Main executable: Contents/MacOS/Demo

### ⚠️ warn `bundle.minimum-system`

LSMinimumSystemVersion absent — users on older macOS crash on launch and your crash reports will look like product bugs.

*hint:* Declare the minimum deployment target.

## signing (3)

### ❌ fail `sign.presence`

The bundle is not code-signed at all — Gatekeeper blocks install and users see “app is damaged” style blockers.

```
codesign: code object is not signed at all
```

*hint:* Sign with a Developer ID identity under hardened runtime, then notarize and staple.

### ⏭️ skip `sign.validity` _(unknown)_

Signature validity skipped: nothing signed.

### ❌ fail `sign.resources`

Contents/\_CodeSignature missing — not a complete signed bundle.

## entitlements (1)

### ⏭️ skip `ent.hardened` _(unknown)_

Entitlements skipped: binary is unsigned.

## notarization (1)

### ⚠️ warn `not.stapled` _(inferred)_

No stapled ticket observed locally. Offline launch acceptance is unproven; assess a clean customer Mac.

```
codesign -dv: no Notarization Ticket line
```

*hint:* Notarize and staple: xcrun notarytool submit → xcrun stapler staple.

## gatekeeper (2)

### ❓ unknown `gatekeeper.assess` _(unknown)_

Gatekeeper assessment not run: spctl may contact Apple, and shipcheck is offline by default. Result is UNKNOWN, not a pass.

*hint:* Re-run with --gatekeeper to opt in (may contact Apple).

### ℹ️ info `gatekeeper.quarantine`

No quarantine xattr (typical for locally-installed or adopted apps).

## architecture (1)

### ❓ unknown `arch.main` _(unknown)_

Could not determine main executable architecture (lipo AND file failed).

```
/Users/demo/Downloads/Demo.app/Contents/MacOS/Demo
```

## asar (1)

### ⚠️ warn `asar.layout`

Neither app.asar nor a loose Resources/app directory found — payload layout is not a recognizable Electron shape.

## native code (1)

### ℹ️ info `native.inventory`

No Mach-O native payload found in the bundle.

## updater (2)

### ℹ️ info `updater.story` _(inferred)_

No updater hints observed in the inspected bundle. Custom code, remote feeds and manual delivery are not established by file absence.

### ❓ unknown `updater.delivery` _(unknown)_

No update check, download, signature verification, install, feed access or end-to-end update rehearsal was performed.

## paths (2)

### ✅ pass `paths.info-plist` _(inferred)_

Info.plist is free of generator-host paths.

### ✅ pass `paths.executables` _(inferred)_

No build-host path text found in 1 scanned Mach-O binary(ies).

## hashes (1)

### ✅ pass `hashes.executables`

SHA-256 recorded for 1 of 1 artifact(s).

```
377bc5e04baff7614ba765935928d5dd1726cd90c109aaeffed98eb362a1d1c6  Contents/MacOS/Demo
```

## Summary

3 pass · 5 info · 3 warn · 3 fail · 3 unknown · 2 skip — verdict: **failures**
