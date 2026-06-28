package com.handshake.browser.core

object BrowserSecurityPolicy {
    fun state(
        targetKind: BrowserTargetKind?,
        proxyAvailable: Boolean,
        syncStatusJson: String?,
        mainFrameHnsStatusCode: Int? = null,
        mainFrameHnsTlsPolicy: HnsPageTlsPolicy? = null,
        mainFrameHnsResolverPolicy: HnsPageResolverPolicy? = null,
    ): SecurityState {
        if (targetKind != BrowserTargetKind.HnsName) {
            return SecurityState.WebPkiOnly
        }
        if (!proxyAvailable) {
            return SecurityState.ProofUnavailable
        }
        if (mainFrameHnsStatusCode?.let { it in 400..599 } == true) {
            return SecurityState.ValidationFailed
        }
        if (mainFrameHnsStatusCode?.let { it in 200..299 } == true) {
            if (mainFrameHnsTlsPolicy == HnsPageTlsPolicy.Dane) {
                if (mainFrameHnsResolverPolicy == HnsPageResolverPolicy.HnsDohCompatibility) {
                    return SecurityState.DaneCompatibility
                }
                return SecurityState.DaneVerified
            }
            if (mainFrameHnsTlsPolicy == HnsPageTlsPolicy.WebPkiFallback) {
                return SecurityState.MixedPolicy
            }
            if (mainFrameHnsResolverPolicy == HnsPageResolverPolicy.HnsDohCompatibility) {
                return SecurityState.HnsCompatibility
            }
            return SecurityState.HnsVerified
        }
        if (
            syncStatusJson.hasSyncStatus("error") ||
            syncStatusJson.hasSyncStatus("seed_failed") ||
            syncStatusJson.hasSyncStatus("peer_failed")
        ) {
            return SecurityState.ProofUnavailable
        }
        if (
            !syncStatusJson.isBehindPeerHeight() &&
            (syncStatusJson.hasSyncStatus("synced") || syncStatusJson.hasSyncStatus("up_to_date"))
        ) {
            return SecurityState.Loading
        }

        return SecurityState.Syncing
    }

    private fun String?.hasSyncStatus(status: String): Boolean =
        this?.contains("\"status\":\"$status\"") == true

    private fun String?.isBehindPeerHeight(): Boolean {
        val json = this ?: return false
        val best = json.longField("bestHeight") ?: return false
        val target = json.longField("bestPeerHeight")
            ?: json.longField("estimatedTipHeight")
            ?: return false
        return target > best
    }

    private fun String.longField(name: String): Long? {
        val pattern = """"$name"\s*:\s*(null|-?\d+)""".toRegex()
        val value = pattern.find(this)?.groupValues?.getOrNull(1) ?: return null
        return value.takeUnless { it == "null" }?.toLongOrNull()
    }
}
