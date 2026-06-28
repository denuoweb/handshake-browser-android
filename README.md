# Handshake Browser

Android HNS-native browser with a Rust resolver core.

## Layout

- `rust/`: Cargo workspace for consensus primitives, header chain, Urkel proof interfaces, resolver, DNSSEC, DANE, transport, gateway, cache, and Android FFI.
- `rust/fuzz/`: `cargo-fuzz` parser harnesses for DNS, HNS resource values, P2P frames, Urkel proofs, TLSA records, and X.509 SPKI extraction.
- `android/`: Kotlin Android browser shell with WebView, URL classification, loopback proxy setup, and JNI bridge.
- `fixtures/`: Header, Urkel, and DNS fixture slots for HSD/HNSD comparison data.
- `docs/`: Architecture, security model, version audit, and milestone notes.
- `docs/sync-audit.md`: first-run sync path, progress UI, and remaining sync-speed bottlenecks.
- `scripts/`: Local validation helpers.

## Current Scope

- Parses and serializes Handshake block headers.
- Computes Handshake mainnet genesis PoW hash using the HSD header algorithm.
- Validates Handshake TLD syntax and derives HSD-compatible SHA3-256 name hashes.
- Provides typed hash, height, target, and chainwork primitives.
- Stores headers behind an injectable trait with in-memory and SQLite implementations, persists a canonical `hash_by_height` index for reorg-aware best-chain lookups, appends canonical tip updates for normal chain growth, validates the exact mainnet genesis header, enforces HSD-compatible mainnet difficulty retarget bits, and rejects non-genesis headers that fail proof-of-work.
- Parses and synthesizes bounded DNS messages, questions, names, resource records, and RFC 9460 SVCB/HTTPS RDATA.
- Decodes HSD name resource values into DNS-style DS, NS, in-zone glue A/AAAA, synthetic glue A/AAAA, and TXT records.
- Parses DNSSEC DNSKEY/DS/RRSIG/NSEC/NSEC3 records, computes RFC 4034 key tags, verifies SHA-1, SHA-256, and SHA-384 DS-to-DNSKEY delegation links, builds canonical RRSIG signed data including canonical RDATA names for CNAME, NS, SOA, SRV, and SVCB/HTTPS TargetName, verifies legacy RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, and Ed25519 RRset signatures, and composes those checks into fail-closed signed-RRset, delegated-chain, NSEC no-data, NSEC name-range, NSEC name-error, and RFC 5155 NSEC3 denial validators.
- Encodes and decodes the HSD packet subset needed for header sync and proof requests, including HSD-compatible 9-byte wire framing, 88-byte HSD network addresses in version and addr packets, version/verack ordering tolerance, advisory/unknown packet tolerance during sync waits, transient-failure peer recovery with bounded malformed-peer bans, and a blocking TCP peer connection for getaddr, getheaders, and getproof flows.
- Adds parser fuzz smoke targets for DNS messages/names/SVCB, HNS resource values, P2P frames/payloads, Urkel proofs, TLSA records, and bounded X.509 SPKI extraction.
- Provides sync coordinators for version/verack, getaddr/addr peer discovery, getheaders/headers ingestion with duplicate-header tolerance, locator construction, remote-height-aware no-op sync when peers are not ahead of the local best header, bounded multi-batch header sync across selected peers with persisted peer outcomes, same-run getaddr discovery rotation toward the peer-table target, Android first-run catch-up status that stays `syncing` while the known or estimated target is ahead of local best height, DNS seed refresh while the peer table is below target, tracked getproof/proof flow control, upstream-compatible Urkel proof verification, verified HSD `NameState.data` value handoff, and proof scheduling into the resolver resource-value store.
- Implements DANE TLSA matching, bounded X.509 certificate SPKI extraction, chain-aware EE/TA TLSA policy, and fail-closed HNS/WebPKI TLS decisions.
- Provides peer scoring, banning, static peer seeding, HSD-compatible DNS seed discovery, bounded rotating getaddr peer discovery, SQLite peer-state persistence, address-group-aware outbound peer selection, LRU-bounded TTL resolver positive and verified-negative caching primitives, in-memory and SQLite verified resource-value providers, resource-cache byte accounting, chain-root/height anchoring, current-tip cache invalidation, active cap enforcement, clear-cache support, a proof-provider-backed HNS resolver boundary that can extract verified HSD resource values, distinguishes verified non-inclusion from existing names with no origin address, extracts final-label HNS roots for dotted HNS hosts, hydrates out-of-zone HNS nameserver addresses from their own verified root proofs, and filters proven DNS-style records fail-closed, and a DNSSEC-gated delegation boundary for HNS roots with NS/DS records backed by authoritative UDP DNS with TCP fallback on truncation, transport failure, or invalid UDP responses, signed positive RRset validation, bounded CNAME-chain validation, signed child-referral validation with child CNAME-chain handling, parent/child NSEC/NSEC3 no-data validation, and delegated NXDOMAIN name-error validation.
- Provides bounded HTTP/1.1 origin transport over TCP or rustls TLS, HTTPS HTTP/2 origin transport over Tokio/Rustls, and HTTPS HTTP/3 origin transport over Quinn/h3 with DANE validation bound to the QUIC TLS handshake, with gateway routing only from owner-matching secure A/AAAA answers or validated CNAME-chain terminal A/AAAA answers to transport connect addresses, delegated origin A/AAAA lookup when Android starts from all root records, exact `_port._tcp.host` DNSSEC-secure TLSA lookup for DANE policy, strict and compatibility HNS HTTPS policy modes, HTTPS/SVCB ALPN and service-port policy selection constrained to implemented origin protocols, HTTP/1.1 default fallback when SVCB permits it, fail-closed origin response framing for unsupported transfer codings or ambiguous lengths, stream-to-writer decoded response bodies, and actionable fail-closed handling when HNS resolution lacks an origin address or delegated nameserver responses are invalid.
- Adds gateway-time live proof fetching on verified-resource cache miss from peers at or above the local anchor height, storing Urkel-verified values anchored to the current best header before origin routing, and an Android-only AD-gated HNS DoH compatibility fallback for delegated nameserver failures after the proof-backed root path has run; remaining DNSSEC algorithms, HNS WebSocket/HTTP Upgrade stream tunneling, connection pooling/session resumption, and remaining gateway boundaries stay fail-closed or future work.
- Packages the Rust FFI core into the APK for `arm64-v8a` and `x86_64`.
- Adds an Android WebView shell with HNS-aware omnibox classification that defaults bare HNS names to HTTPS, routes dotted hosts with non-common-ICANN final labels as HNS, directly intercepts bodyless HNS WebView and Service Worker HTTP/HTTPS requests into the native gateway with file-backed response bodies, follows bounded redirects that remain inside HNS resolution policy, reports main-frame HNS gateway failures plus DANE/WebPKI and resolver compatibility policy in the left-side toolbar security state, a shared reserved-name host policy, a sync-aware HNS security label policy, a `dataSync` foreground service that owns repeated native sync and broadcasts status snapshots, automatic first-run sync catch-up with active retry intervals while behind, a main-screen block progress bar with live-polled `bestHeight` and target fallback plus a separate WebView loading bar, hamburger-menu access to back, forward, refresh, and Settings, a Settings dashboard for diagnostics, cookie options, resolver-cache clearing, legal/user-agreement content, source information, and donation links, a diagnostic-only sync/cache status surface with manual sync triggering, explicit syncing/up-to-date vs peer-failed outcomes, per-peer sync failure stages, AD-gated HNS DoH compatibility resolution for delegated nameserver failures with explicit `via DoH` UI labels, and actionable HNS error pages for proof, name-not-found, nameserver, DNSSEC, DANE, transport, and origin-address failures that include the requested URL, and a randomized-port loopback HTTP/CONNECT proxy that routes valid HNS HTTP requests through the native gateway using the persistent verified-resource cache, forwards bounded headers, Range requests, and request bodies, rejects unsupported transfer-encoded, ambiguous-length, and HNS WebSocket/HTTP Upgrade requests before native routing, avoids reserved non-HNS single-label names, terminates HNS CONNECT locally with per-host native self-signed certificates, preserves normal ICANN HTTP Upgrade tunnels, and only proceeds past WebView SSL errors when the presented local certificate fingerprint exactly matches the generated HNS host pin.

## Validate

```sh
./scripts/check.sh
./scripts/fuzz-smoke.sh
```

Android builds on ARM64 host use APK Workbench:

```sh
APK_WORKBENCH="$HOME/APK_Workbench"
GRADLE="$APK_WORKBENCH/scripts/dev/apkw-gradle.sh"

./scripts/build-android.sh

"$GRADLE" --project-dir "$PWD/android" testDebugUnitTest

"$GRADLE" \
  --project-dir "$PWD/android" \
  connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.handshake.browser.net.HnsConnectInstrumentationTest
```

The debug APK is written to `android/app/build/outputs/apk/debug/app-debug.apk`.

Debug/demo builds are unsigned beyond the default Android debug key and are intended for testing only. The diagnostics screen identifies Denuo Web, LLC as publisher, shows the build channel and license, and states that donations are optional and unlock no app features.

The APK build runs `scripts/build-rust-android.sh` through Gradle, builds `android-ffi` with `cargo-ndk`, strips the generated `.so` files with the APK Workbench NDK `llvm-objcopy`, and packages them under `lib/<abi>/libhns_browser_ffi.so`.

## Support

Donations are optional and do not unlock any app features.

- HNS donation address: `hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`

## License

This repository is source-available under the PolyForm Noncommercial License 1.0.0. Noncommercial use, study, modification, and redistribution are allowed under the license. Commercial use requires separate written permission from Denuo Web, LLC.

Source code: https://github.com/denuoweb/handshake-browser-android
