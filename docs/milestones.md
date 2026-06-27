# Milestones

## Milestone 1: Rust Proof Kernel

- Header parsing and serialization.
- Header PoW hash parity with HSD genesis fixtures.
- HSD-compatible mainnet difficulty retarget validation.
- Header store abstraction, SQLite persistence, canonical hash-by-height indexing, and best-tip selection.
- Handshake `getheaders`, `headers`, `getproof`, and `proof` payload codec.
- HSD-compatible 9-byte P2P frame encoder/decoder.
- Blocking TCP peer connection for version/verack, getaddr, getheaders, and getproof flows.
- Header sync session state machine for version/verack and request/response sequencing.
- Peer scoring and outbound selection policy.
- Static peer seeding, HSD-compatible DNS seed discovery, bounded getaddr peer discovery, address-group-aware peer diversity, and SQLite peer-state persistence.
- HSD-compatible Handshake name validation and SHA3-256 name-hash derivation.
- Urkel proof parser and verifier boundary.
- HSD resource decoder for DS, NS, GLUE4/GLUE6, SYNTH4/SYNTH6, and TXT records.
- Verified Urkel proof-value handoff.
- Proof scheduler from TCP getproof responses into the resolver resource-value store.
- Gateway cache-miss proof fetching into the verified resource-value store.
- Parser fuzz smoke targets.

## Milestone 2: Live HNS Sync

- Peer manager, TCP peer connection, and sync coordinator scaffolding.
- Version/verack and getheaders/headers session flow.
- Persistent header store.
- Persistent peer-state store.
- Bounded multi-batch header sync runner with selected peers, scoring, and persistence.
- Proof request lifecycle scaffolding with Urkel proof verification.
- Proof-provider-backed HNS resolver boundary with verified resource-value extraction and proven-record filtering.
- Verified HNS non-inclusion surfaced separately from existing names with no origin address.
- In-memory and SQLite verified resource-value providers for sync-to-resolver handoff.
- Resource-cache byte accounting, chain-root/height anchoring, current-tip invalidation, clear, oldest-entry eviction, and active sync-time cap enforcement.
- TCP proof scheduler and gateway cache-miss proof fetcher that store verified resource values for resolver use.
- Gateway fail-closed guard when HNS resolution has no origin A/AAAA connect address.

## Milestone 3: DANE Core

- DNSSEC DNSKEY/DS delegation-link primitives with SHA-1, SHA-256, and SHA-384 DS validation digests.
- DNS SVCB/HTTPS RDATA parsing and DNSSEC canonicalization.
- DNSSEC RRSIG canonical signed-data construction.
- DNSSEC canonical RDATA name handling for CNAME, NS, SOA, SRV, SVCB/HTTPS, and RRSIG signer names.
- DNSSEC ECDSA P-256/SHA-256 RRset signature validation.
- DNSSEC ECDSA P-384/SHA-384 RRset signature validation.
- DNSSEC legacy RSA/SHA-1, RSA/SHA-256, and RSA/SHA-512 RRset signature validation.
- DNSSEC Ed25519 RRset signature validation.
- DNSSEC signed-RRset validator composed from DS, DNSKEY, and RRSIG checks.
- DNSSEC delegated-chain validator composed from authenticated DS and DNSKEY RRsets.
- DNSSEC NSEC no-data, name-range, and name-error denial validation.
- DNSSEC RFC 5155 NSEC3 no-data, name-error, DS opt-out, wildcard, and referral denial validation.
- DNSSEC remaining algorithm and NSEC3 hash-transition support.
- TLSA validation matrix.
- DANE policy engine.
- Certificate/SPKI extraction.

## Milestone 4: Origin Transport

- Bounded HTTP/1.1 TCP fetch.
- TCP TLS fetch with rustls.
- DNSSEC-gated TLSA/DANE validation during TLS handshake.
- HTTP/2 fetch.
- QUIC/HTTP/3 fetch.

## Milestone 5: Android Browser

- WebView shell.
- ProxyController integration.
- Loopback HTTP/CONNECT proxy with native persistent-cache HNS HTTP routing, WebView and Service Worker bodyless HNS HTTP/HTTPS request interception with file-backed decoded response bodies, bounded HNS redirect following, bounded header/body forwarding, reserved-name filtering, local HTTPS termination for HNS CONNECT using exact generated-certificate fingerprint pins, ICANN HTTP Upgrade tunnel preservation, and explicit fail-closed HNS WebSocket/HTTP Upgrade handling until native stream tunneling exists.
- Packaged Rust JNI library.
- Android `dataSync` foreground service, native sync scheduler, sync status broadcasts, live-polled first-page sync progress bar with target fallback, separate WebView loading bar, hamburger refresh/diagnostics menu, automatic active first-run catch-up while peer height or estimated tip is ahead, sync/cache diagnostics status with manual sync triggering, explicit syncing/up-to-date vs peer-failed outcomes, per-peer sync failure stages, and resolver-cache clearing.
- HNS omnibox rules.
- Security and diagnostics UI.

## Milestone 6: Hardening

- Enforced cache caps, current-tip cache invalidation, clear-cache action, and cache-size diagnostics.
- Device matrix.
- Fuzzing expansion.
- Battery and network optimization.
- Security review.
