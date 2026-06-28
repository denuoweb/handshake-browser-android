# Architecture

The product is an Android browser with a Rust core, not a system-wide resolver. The browser owns URL interpretation, HNS resolution policy, DANE policy, transport policy, and validation error UX.

## Layers

```text
Android UI / Browser Shell
  -> Kotlin app services
  -> WebView + AndroidX ProxyController
  -> Local loopback gateway
  -> Rust core via JNI/FFI
  -> HNS resolver, DNSSEC, DANE, transport, cache
  -> HNS peers, ICANN DNS, TCP TLS, QUIC/HTTP3
```

## Rust Crates

- `hns-core`: consensus-neutral primitives, HSD-compatible name validation and name-hash derivation, hashes, bounded parsing, Handshake headers, DNS/TLSA wire primitives, RFC 9460 SVCB/HTTPS RDATA parsing, and HSD name resource value decoding.
- `hns-chain`: header storage, chainwork, HSD-compatible mainnet difficulty retarget validation, best-tip selection, restartable state interfaces, canonical `hash_by_height` indexing for reorg-aware height lookups, and append-only canonical tip promotion for normal chain growth.
- `hns-p2p`: Handshake packet payload codec, HSD-compatible frame encoder/decoder, blocking TCP peer connection, header-sync session state, static peer seeding, HSD-compatible DNS seed discovery, bounded getaddr/addr peer discovery with discovery-rotation selection, SQLite peer-state persistence, peer score tracking, transient-failure recovery with bounded malformed-peer bans, and address-group-aware outbound peer selection.
- `hns-sync`: header batch and proof lifecycle coordinators connecting P2P sync actions to chain validation, remote-height-aware no-op sync when selected peers are not ahead, bounded multi-batch header sync across selected peers with persisted peer outcomes, successful-peer getaddr discovery plus same-run probing of additional unqueried peers toward the peer-table target, upstream-compatible Urkel proof verification, verified HSD `NameState.data` value handoff, and resolver resource-value storage. Non-genesis headers must match expected mainnet difficulty bits and satisfy proof-of-work before storage.
- `hns-urkel`: Bounded Urkel proof parsing and BLAKE2b-256 verification for inclusion, deadend, short-prefix, and collision proofs, with a separate fail-closed verifier for unwired runtime paths.
- `hns-resolver`: URL/name classification, final-label HNS root extraction for single-label and dotted HNS hosts, verified HSD resource-value extraction, verified non-inclusion state, resource-value provider adapter, in-memory and SQLite verified resource-value providers, resource-cache byte accounting, chain-root/height anchoring, cap enforcement, clear-cache support, proof-provider-backed answer filtering and out-of-zone HNS nameserver address hydration, DNSSEC-gated delegation boundary for HNS roots with NS/DS records, authoritative UDP DNS with TCP fallback for delegated HNS zones, signed positive RRset validation, bounded CNAME-chain validation, signed child-referral validation with child CNAME-chain handling, parent/child NSEC/NSEC3 no-data and NXDOMAIN name-error validation, TTL cache wrapper, and resolver-facing answer types.
- `hns-dnssec`: DNSSEC validation boundary with DNSKEY/DS/RRSIG/NSEC/NSEC3 parsing, RFC 4034 key-tag computation, SHA-1, SHA-256, and SHA-384 delegation-link verification, canonical signed-data construction including canonical RDATA names for CNAME, NS, SOA, SRV, SVCB/HTTPS, RRSIG signer names, legacy RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, and Ed25519 RRset signature verification, signed DNSKEY RRset checks, composed delegated-chain validation, NSEC no-data/name-range/name-error denial validation, and RFC 5155 NSEC3 no-data/name-error/DS/wildcard/referral denial validation. Unsupported algorithms and unknown NSEC3 hash algorithms remain fail-closed.
- `hns-dane`: TLSA record parsing, bounded X.509 SPKI extraction, chain-aware DANE EE/TA certificate/SPKI matching, PKIX-usage WebPKI gating, and HNS/WebPKI TLS policy decisions.
- `hns-transport`: bounded HTTP/1.1 origin transport over TCP or rustls TLS, HTTPS HTTP/2 origin transport over Tokio/Rustls, HTTPS HTTP/3 origin transport over Quinn/h3 with QUIC TLS bound to the same DNSSEC-gated TLSA/DANE certificate policy, WebPKI fallback, fail-closed response framing for unsupported transfer codings or ambiguous lengths, decoded response body streaming to caller-provided writers, and explicit fail-closed rejection for HTTP Upgrade requests before hop-by-hop headers can be stripped. Connection pooling, session resumption, Alt-Svc promotion, and HNS WebSocket stream tunneling remain future work.
- `hns-gateway`: loopback gateway interfaces, secure-resolution checks, owner-scoped resolved A/AAAA connect-address routing with validated CNAME-chain terminal address support, delegated origin A/AAAA lookup for all-record Android gateway starts and origin-focused A/AAAA requests, separate HTTPS/SVCB service lookup for address-only answers, HTTPS/SVCB ALPN and service-port policy selection constrained to configured origin protocol support, HTTP/1.1 default fallback when SVCB does not disable default ALPN, fail-closed HNS no-address/nameserver handling, exact service-owner DNSSEC-secure TLSA lookup, strict and compatibility HNS HTTPS policy modes, and validation error mapping.
- `hns-cache`: bounded TTL cache primitives.
- `android-ffi`: FFI surface consumed by the Android app, including diagnostics, actionable HNS error mapping for verified name-not-found, proof, nameserver, DNSSEC, DANE, transport, and origin-address failures, a foreground-service-called native header sync tick with explicit `syncing`, `synced`, `up_to_date`, `peer_failed`, `seed_failed`, and `idle` outcome labels, estimated-tip sync progress when peer height is not yet known, high-batch Android catch-up runs, sync-time current-tip resource-cache invalidation and cap enforcement, a no-network sync/cache status reader that reports `up_to_date` when stored peer heights are not ahead of the local best header, resolver-cache clearing, and native gateway HTTP response paths backed by current-tip anchored persistent verified resources plus live Urkel proof fetching from peers at or above the local anchor height on cache miss, authoritative DNSSEC delegated resolver wiring, AD-gated HNS DoH compatibility fallback for delegated nameserver failures, Android HNS HTTPS compatibility-mode selection, observable DANE/WebPKI and resolver-policy headers, bounded header/body and Range request forwarding, and file-backed decoded response bodies for WebView HNS interception.
- `rust/fuzz`: parser fuzz smoke targets for DNS messages/names/SVCB, HNS resource values, P2P frames/payloads, Urkel proofs, TLSA records, and X.509 SPKI extraction.

## Android Modules

- `MainActivity`: WebView browser shell with custom omnibox, left-side security status, shared HNS host policy, live-polled first-page sync progress bar and target stats, a separate WebView loading bar, hamburger-menu back/forward/refresh/settings actions, Service Worker HNS interception setup, security state, and navigation controls.
- `SettingsActivity`: settings dashboard linking to diagnostics, cookie options, legal/user-agreement content, native resolver-cache clearing, and donation links.
- `CookieSettingsActivity`: cookie preferences with persisted third-party cookie blocking and delete-cookies action.
- `LegalActivity`: license, user agreement, build label, publisher-in-license language, and source-code link.
- `BrowserUrlClassifier`: classifies searches, normal web URLs, and HNS names. Bare HNS names default to `https://`, and dotted hosts with non-common-ICANN final labels route through native HNS interception instead of Chromium DNS resolution.
- `BrowserSecurityPolicy`: maps target kind, proxy availability, native sync outcome status, main-frame HNS gateway response status, DANE/WebPKI policy, and resolver policy into the toolbar security state so HNS names do not stay verified after a native gateway failure and DoH compatibility loads are visibly labeled.
- `HnsProxyController`: runtime-gated AndroidX WebKit proxy configuration pointed at the currently bound randomized loopback gateway port.
- `HnsSyncForegroundService`: Android 14+ `dataSync` foreground service that owns repeated native sync, starts automatically with the main activity, keeps a user-visible notification active, and broadcasts sync status snapshots with explicit progress and per-peer failure stages to the UI.
- `HnsSyncScheduler`: single-threaded scheduler used by the foreground service to call the native sync tick and publish sync status snapshots, using active catch-up intervals while the target is ahead, retry intervals after peer/seed failures, and 10-minute idle intervals after catch-up.
- `HnsWebViewGatewayInterceptor`: Shared WebView and Service Worker request interception for bodyless HNS HTTP/HTTPS requests, routing them through the native gateway without Chromium CONNECT so explicit HNS HTTPS can use Rust TLS/DANE policy, with file-backed decoded response bodies, bounded redirect following for targets that remain inside HNS resolution policy, main-frame status reporting for toolbar state, and proxy fallback for body-bearing HNS requests only after the loopback proxy is active.
- `HnsServiceWorkerGatewayClient`: Service Worker fetch interception that reuses the WebView HNS gateway policy instead of letting worker fetches bypass native HNS validation.
- `LoopbackProxyServer`: app-owned randomized-port loopback HTTP/CONNECT proxy for WebView traffic. It forwards normal ICANN HTTP, preserves normal ICANN HTTP Upgrade tunnels, shares the omnibox reserved-name HNS host policy, rejects unsupported transfer-encoded, ambiguous-length, or HNS Upgrade requests before origin/native routing, routes HNS HTTP requests with bounded headers and bodies through the native persistent-cache gateway path, tunnels normal ICANN CONNECT traffic, and terminates HNS CONNECT locally with per-host native self-signed certificates whose fingerprints must be pinned before WebView may proceed past the expected local certificate error.
- `NativeBridge`: JNI/FFI load boundary for the Rust shared library.

Android builds are compiled through APK Workbench on this ARM64 host so Gradle receives the managed SDK/NDK, page-size profile, and ARM64 `aapt2` override. Gradle also invokes `scripts/build-rust-android.sh` to cross-compile and package `libhns_browser_ffi.so` for `arm64-v8a` and `x86_64`.

## Security Defaults

- HNS proof, DNSSEC, and DANE failures fail closed.
- Local gateway binds to a randomized loopback port only.
- Android WebView proxy use is gated by `WebViewFeature.PROXY_OVERRIDE`.
- URL classification never sends single-label HNS names to a search provider before local HNS resolution is attempted, and reserved non-HNS single-label names are not shown as HNS state.
