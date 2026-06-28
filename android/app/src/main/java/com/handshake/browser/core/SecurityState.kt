package com.handshake.browser.core

enum class SecurityState {
    Syncing,
    Loading,
    HnsVerified,
    HnsCompatibility,
    DaneVerified,
    DaneCompatibility,
    WebPkiOnly,
    MixedPolicy,
    ValidationFailed,
    ProofUnavailable,
}

enum class HnsPageTlsPolicy {
    Dane,
    WebPkiFallback,
}

enum class HnsPageResolverPolicy {
    HnsDohCompatibility,
}
