# Sync Startup Audit

## Current First-Run Path

- `MainActivity.onStart` starts `HnsSyncForegroundService` automatically, so first install no longer depends on opening Diagnostics and pressing `Run sync now`.
- `HnsSyncScheduler` runs immediately, then uses active polling while the local `bestHeight` is below the known or estimated target, retry polling for peer/seed discovery failures, and a 10-minute idle poll after the app is caught up.
- The native Android sync tick requests up to 192 header batches per peer per run, which is enough to cover current mainnet-scale catch-up in one or a small number of foreground ticks when a healthy peer serves full batches.
- Seeded peers are persisted before the long header run starts, and DNS seeds are refreshed while the peer table is below target, so a killed or interrupted first run does not leave the peer database empty after headers have already advanced.
- Native status reports `syncing` whenever persisted peer height or the estimated mainnet tip is still ahead of local best height, even if the current tick accepted headers. `synced` is reserved for ticks that accepted headers and reached the known peer target; no-network status reports `up_to_date` when stored peers are not ahead.

## User-Visible Progress

- The main browser screen shows a horizontal sync progress bar directly under the omnibox toolbar.
- The main browser screen polls lightweight native sync status while visible, so `bestHeight` and the progress bar move during long native header runs instead of waiting for the foreground-service tick to finish.
- The status line under the progress bar shows status, `bestHeight`, a single `target` height while syncing, peer count, and the latest accepted header count when present; `bestPeerHeight` is shown only after the known peer target has been reached.
- A second horizontal loading bar sits below the block-sync info and tracks WebView page-load progress while HNS proof/DANE/origin work is running.
- HNS gateway error bodies include the requested URL above the status line so repeated 502 pages can be distinguished at a glance.
- The foreground notification uses the same parsed sync progress so Android’s persistent sync notification reflects catch-up progress instead of a generic running state.

## Remaining Speed Bottlenecks

- Initial sync still downloads and validates headers from live peers at first run; the APK does not yet ship a recent signed/checkpointed header snapshot.
- Proof data is still fetched on demand for requested HNS names rather than prefetching popular names.
- Peer quality dominates first-run time. The current path seeds peers automatically and retries quickly while behind, but poor peers can still slow catch-up until peer scoring rotates to better peers.
