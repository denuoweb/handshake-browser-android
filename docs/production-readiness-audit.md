# Production Readiness Audit

Last audited: 2026-06-29

This audit treats the app as a Play Store closed-testing candidate and checks the shipped Android surface from the outside in: manifest, WebView behavior, release build configuration, network/privacy declarations, diagnostic UI, and release automation.

## Release Candidate Findings

| Area | Status | Finding |
| --- | --- | --- |
| Android release build | Ready | Release builds are non-debuggable, minified, resource-shrunk, upload-signed when Play signing env vars are present, and verified for required 64-bit native libraries. |
| Manifest exposure | Ready | Only the launcher activity is exported. Diagnostics, settings, HNS inspectors, history, downloads, and the sync service are not exported. |
| Backup / transfer | Ready | App backup and device-transfer extraction are disabled for local browsing, cookies-adjacent prefs, downloads records, diagnostics, resolver cache, and HNS sync/cache state. |
| Cleartext policy | Ready | Cleartext is disabled globally with a loopback-only exception for the local gateway. |
| WebView hardening | Ready | Mixed content is blocked, Safe Browsing is enabled, file/content access is disabled, native JavaScript bridges are removed, and WebView debugging follows `BuildConfig.DEBUG`. |
| Data collection posture | Ready for declaration | No ads, analytics SDKs, developer accounts, location, contacts, SMS, camera, microphone, or advertising ID access were found in app code. Browser requests, HNS peer traffic, DNS, and optional compatibility DoH remain user-visible app functionality. |
| HNS diagnostics | Ready | Resolver trace, HNS proof details, TLSA/DANE inspector, gateway event log, and diagnostic bundle export are present. |
| Production UI | Improved | Main menu now keeps user browsing controls and HNS page-specific inspectors; full app diagnostics live under Settings. Toolbar status text is bounded so it does not crowd the omnibar on small screens. |
| Google Play closed testing | Externally blocked | The signed AAB exists, but local API upload is blocked until a Play-linked service account or correctly scoped Android Publisher token is available. Manual Play Console upload remains valid. |

## Applied Cleanup

- Removed the general Diagnostics shortcut from the main hamburger menu so Diagnostics remains a Settings tool instead of a primary browsing action.
- Constrained the toolbar security label and sync summary text to avoid layout crowding on small devices.
- Clarified Strict HNS mode wording: compatibility DoH fallback is described as available only after local HNS proof path verification and direct delegated resolution failure.
- Added `scripts/play-upload-closed-testing.sh` for closed testing upload once Play API credentials are available.
- Documented that the standard Play closed-testing API track is `alpha` unless the Play Console app uses a custom closed track.

## Remaining Non-Code Work

- Upload `dist/play-store/hns-browser-v0.2.2-play-upload-signed.aab` to the closed testing track in Play Console.
- Complete the Foreground service declaration with the short sync demo video.
- Complete Data safety, App access, Content rating, Target audience, Ads, and Privacy policy declarations using `docs/play-store-readiness.md`.
- Add at least 12 opted-in testers and keep closed testing active for the required period if Google applies the new personal-account production-access rule.

## Watch Items

- First-launch notification permission is requested because sync runs as a visible data-sync foreground service. If tester feedback shows the prompt is confusing, add an in-app rationale screen before requesting the permission.
- General-purpose browsing can reach arbitrary third-party web content; keep target audience and content rating conservative.
- HNS WebSocket / HTTP Upgrade for HNS origins remains fail-closed until native stream tunneling is implemented.
- Parallel/ranged header sync remains bounded by Handshake header-chain validation order and peer/protocol pacing; performance work should avoid weakening canonical-header validation.
