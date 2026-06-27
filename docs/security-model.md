# Security Model

## Trust

The app verifies header chainwork, checkpoint ancestry, proof-of-work difficulty, Urkel proofs against header tree roots, DNSSEC chains below HNS delegations, TLSA records, DANE certificate or SPKI matches, and transport downgrade policy.

The default proof-backed path does not trust a single peer, external HNS resolvers, unsigned DNS answers for HNS names, TLSA answers without a valid proof chain, stale caches, or origin certificates that fail active DANE policy. Android compatibility mode may query the configured HNS DoH resolver only after the local HNS proof/delegation path has established the root name and then failed at delegated nameserver transport/validation; those fallback answers are treated as secure only when the DNS response carries authenticated-data.

## Failure Policy

- HNS proof failure: fail closed.
- DNSSEC validation failure: fail closed.
- TLSA exists but DANE validation fails: fail closed.
- Sync stale: block HNS secure state and show a sync-specific browser error.
- Sync attempts that make no progress must distinguish up-to-date peers from all-peer failure.
- Sync catch-up must continue while persisted `bestPeerHeight` or the estimated mainnet tip is greater than local `bestHeight`, regardless of whether the latest native tick accepted headers.
- HNS toolbar state must not show verified unless the proxy is active, the native sync status is `synced` or `up_to_date`, and the current main-frame HNS gateway response has not failed.
- Main-frame HNS gateway 4xx/5xx responses must override ready sync state and show validation failed.
- No-network sync status reads may report `up_to_date` only when stored peer heights are not ahead of a non-genesis local best header.
- Gateway exposure beyond loopback: configuration error.
- Browser-visible HNS gateway errors must identify the failing stage without exposing private request bodies.
- Verified HNS non-inclusion must surface as name-not-found instead of origin-address-missing.

## Review Checklist

- Parsers are bounded and return structured errors.
- Parser fuzz smoke targets cover DNS messages/names/SVCB, HNS resource values, P2P frames/payloads, Urkel proofs, TLSA records, and X.509 SPKI extraction.
- P2P frames reject wrong network magic and payloads above the 8 MB HSD message limit.
- P2P sockets must use bounded frame decoding, connection timeouts, and session-state checks before accepting headers or proofs.
- Header sync must not request additional headers from a peer whose advertised height is not ahead of the local best header.
- Android first-run header sync should use active polling and high-batch native runs while behind, then fall back to idle polling only after stored peer heights are not ahead.
- Transient peer failures must not permanently exhaust the outbound peer pool; malformed consensus data is still scored and cooldown-banned.
- Version packets use HSD's 88-byte network address format rather than Bitcoin's shorter address encoding.
- Version/verack ordering is accepted in either HSD-observed order before the session enters ready state.
- Advisory or unknown P2P packets are ignored while waiting for required sync packets; they do not advance header/proof state.
- Duplicate headers in peer batches are ignored as idempotent sync input; full duplicate-only pages stop the bounded multi-batch loop so a stale peer cannot spin the sync runner, while invalid difficulty bits, invalid proof-of-work, and unknown-parent headers still fail closed.
- No panics on malformed network data.
- No unbounded memory growth from attacker-controlled lengths.
- No Urkel proof request key should be derived from a name that fails Handshake TLD validation.
- No Urkel proof should be accepted unless its BLAKE2b-256 path recomputes the expected tree root for the requested name hash.
- No verified Urkel value should be exposed as resolver records unless its HSD resource payload decodes within bounded type and record limits.
- No HSD Urkel inclusion value should be cached as resolver data until its serialized `NameState` name matches the requested root and only its bounded `data` field is extracted.
- No TCP proof response should be stored for resolver use unless it matches a tracked getproof request and passes Urkel verification.
- No cached verified resource value should be served unless its root label and name hash match the resolver request.
- No chain-anchored cached verified resource value should be served unless its proof tree root and height match the current local best header; sync ticks prune values that are unanchored or not anchored to that current tip.
- No persisted verified resource value should be stored or returned unless its root label and name hash are normalized and matched.
- No proven HNS answer should be returned if the proof name hash or root name mismatches the request.
- No verified HNS non-inclusion should be treated as an existing name with an empty record set.
- No HNS origin connect address should be selected from NS glue or another owner name unless that owner is reached through a DNSSEC-validated CNAME chain from the requested origin owner.
- No HNS origin request that starts from root delegation records should be treated as complete until a secure delegated A/AAAA lookup has been attempted.
- No dotted HNS host should be routed to Chromium DNS when its final label is treated as an HNS root by browser policy.
- No out-of-zone HNS nameserver address should be used unless it comes from a separate verified HNS root proof for that nameserver owner.
- No HNS gateway request should fall back to origin-host system DNS when secure resolution produces no A/AAAA connect address.
- No reserved non-HNS single-label name should be routed into the HNS proxy path or shown as HNS browser state.
- No DNS leak for HNS names.
- No DNSSEC delegation should be treated as secure unless at least one DS digest matches a child DNSKEY.
- No HTTPS/SVCB ALPN or service-port binding should be honored unless the binding is parsed, in service mode, owner-scoped, and limited to supported mandatory keys.
- No address-only HNS answer should skip a separate secure HTTPS/SVCB lookup before TLSA service-owner selection.
- No unsupported DS digest type should be treated as a secure delegation match.
- No RRSIG should be evaluated against non-canonical RRset bytes or outside its validity window.
- No RRset should be treated as DNSSEC-secure unless the delegation link and a covering RRSIG both validate.
- No delegated HNS DNS answer should be treated as secure unless it comes from HNS-proven nameserver glue or synth addresses and validates against the HNS-proven DS RRset.
- No delegated NXDOMAIN response should be treated as malformed solely because its RCODE is NXDOMAIN; it must either validate as secure NSEC/NSEC3 name-error denial or fail closed.
- No empty delegated HNS DNS answer should be treated as secure unless an NSEC or NSEC3 no-data proof validates under the delegated zone DNSKEY.
- No delegated CNAME chain should be followed outside the HNS-proven delegated zone or beyond the bounded CNAME-chain limit.
- No child referral below a delegated HNS zone should be followed as secure unless the HNS-proven parent DS validates the parent DNSKEY, the child DS RRset validates under that parent DNSKEY, and the child answer validates under a DS-matched self-signed child DNSKEY.
- No empty child-zone answer below a delegated HNS zone should be treated as secure unless the parent DNSKEY chain, child DS RRset, child DNSKEY RRset, and child NSEC/NSEC3 no-data proof all validate.
- No DNSSEC signature should depend on mixed-case RDATA owner names or signer names.
- No SVCB/HTTPS RRset should be signed or trusted using compressed or non-canonical TargetName bytes.
- No delegated child DNSKEY RRset should be trusted unless its DS RRset is signed by the parent and the child DNSKEY RRset is self-signed.
- No unsupported DNSSEC signature algorithm should be treated as validated.
- No malformed DNSSEC public key should be treated as validated.
- No malformed ECDSA or Ed25519 DNSSEC public key or signature should be treated as validated.
- No HTTPS/SVCB ALPN value should cause the gateway to select an origin protocol that the configured transport does not support; if SVCB disables default ALPN and no supported protocol remains, fail closed.
- No NSEC denial proof should be accepted unless the NSEC RRset signature validates first.
- No NSEC name error should be accepted unless the queried name is covered and the applicable wildcard under the closest encloser is also denied.
- No NSEC3 denial proof should be accepted unless every participating NSEC3 RRset signature validates first.
- No NSEC3 name error should be accepted unless the closest encloser matches, the next closer is covered, and the applicable wildcard is also denied.
- No NSEC3 opt-out proof should set a secure-denial outcome; it is surfaced only as an insecure-delegation outcome.
- No NSEC3 hash algorithm other than SHA-1 should be accepted until a safe transition mechanism is implemented.
- No TLSA downgrade without an explicit policy event.
- No TLSA record should influence HTTPS trust unless its exact `_port._tcp.host` resolver result is DNSSEC-secure.
- No HNS-strict HTTPS connection should proceed without a DNSSEC-secure TLSA match.
- No HNS compatibility-mode HTTPS connection should be labeled as DANE verified when it used WebPKI fallback; the Android toolbar must show the explicit mixed `HNS + WebPKI` state.
- No HNS DoH compatibility fallback answer should be treated as secure unless the response matches the query tuple and carries the DNS authenticated-data bit.
- No page resolved through the HNS DoH compatibility fallback should be labeled as plain local `DANE verified` or `HNS verified`; the toolbar must show an explicit `via DoH` compatibility state.
- No unbounded or panic-prone X.509 parsing for DANE SPKI selector matching.
- No QUIC downgrade without an explicit policy event.
- No local gateway listener beyond `127.0.0.1` or `::1`.
- No origin fetch unless the gateway resolution name matches the requested origin host.
- No intercepted HNS redirect should be followed unless the target remains inside HNS resolution policy and the redirect chain stays under the configured bound.
- No main-frame HNS gateway 4xx/5xx response should leave the toolbar in verified state.
- No HNS origin connect attempt should use origin-host system DNS when secure resolution has not produced an explicit connect address.
- No insecure resolver result when gateway secure-resolution mode is enabled.
- No proxy request body should be forwarded or dropped unless HTTP/1.1 framing is unambiguous and supported.
- No origin HTTP response body should be accepted unless HTTP/1.1 framing is unambiguous and supported.
- No decoded chunked origin response should be exposed to WebView with stale `Transfer-Encoding` or mismatched `Content-Length` framing; native gateway file-backed bodies are returned with fixed decoded lengths.
- No WebView SSL error should call `proceed()` unless the requested URL is an HNS HTTPS URL and the presented certificate's SHA-256 fingerprint exactly matches the local certificate generated and pinned for that HNS host.
- No HNS WebSocket or HTTP Upgrade request should be silently downgraded to a normal GET by stripping hop-by-hop Upgrade headers; until native stream tunneling is implemented, these requests must fail closed before native gateway routing.
- Browser proxy listener currently binds `127.0.0.1` only, routes HNS HTTP through the native persistent-cache gateway path, preserves normal ICANN HTTP Upgrade tunnels, defaults bare HNS omnibox entries to HTTPS native interception, directly intercepts bodyless HNS WebView and Service Worker HTTP/HTTPS requests into the native gateway with file-backed response bodies, terminates HNS CONNECT locally before routing the decrypted bounded HTTP/1.1 request through the same native gateway path, and fails HNS Upgrade requests closed.
