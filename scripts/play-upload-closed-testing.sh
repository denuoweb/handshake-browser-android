#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [signed-release.aab]" >&2
  exit 2
fi

package_name="${PLAY_PACKAGE:-com.handshake.browser}"
track_name="${PLAY_TRACK:-alpha}"
release_status="${PLAY_RELEASE_STATUS:-completed}"
aab_path="${1:-dist/play-store/hns-browser-v0.2.4-play-upload-signed.aab}"
release_name="${PLAY_RELEASE_NAME:-HNS Browser 0.2.4}"
release_notes="${PLAY_RELEASE_NOTES:-Production cleanup and HNS resolver reliability fixes for closed testing.}"

if [[ ! -f "$aab_path" ]]; then
  echo "AAB not found: $aab_path" >&2
  exit 1
fi

if [[ -n "${PLAY_ACCESS_TOKEN:-}" ]]; then
  access_token="$PLAY_ACCESS_TOKEN"
elif command -v gcloud >/dev/null 2>&1; then
  access_token="$(gcloud auth print-access-token)"
else
  echo "Set PLAY_ACCESS_TOKEN or install/login with gcloud." >&2
  exit 1
fi

api_base="https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${package_name}"
upload_base="https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/${package_name}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

json_get() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path, key = sys.argv[1:3]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
value = data
for part in key.split("."):
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value[part]
print(value)
PY
}

show_error() {
  python3 - "$1" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
except Exception:
    print(open(path, "r", encoding="utf-8", errors="replace").read()[:4000])
else:
    print(json.dumps(data.get("error", data), indent=2)[:4000])
PY
}

request() {
  local method="$1"
  local url="$2"
  local output="$3"
  shift 3
  local http
  http="$(curl -sS -o "$output" -w '%{http_code}' -X "$method" \
    -H "Authorization: Bearer ${access_token}" \
    "$@" \
    "$url")"
  if [[ "$http" -lt 200 || "$http" -gt 299 ]]; then
    echo "Request failed (${http}): ${method} ${url}" >&2
    show_error "$output" >&2
    exit 1
  fi
}

edit_json="$tmpdir/edit.json"
request POST "${api_base}/edits" "$edit_json" -H "Content-Type: application/json"
edit_id="$(json_get "$edit_json" id)"
echo "Created Play edit: ${edit_id}"

bundle_json="$tmpdir/bundle.json"
request POST "${upload_base}/edits/${edit_id}/bundles?uploadType=media" "$bundle_json" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${aab_path}"
version_code="$(json_get "$bundle_json" versionCode)"
echo "Uploaded bundle versionCode: ${version_code}"

track_body="$tmpdir/track-body.json"
python3 - "$track_body" "$version_code" "$release_status" "$release_name" "$release_notes" <<'PY'
import json
import sys

path, version_code, status, name, notes = sys.argv[1:6]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({
        "releases": [{
            "versionCodes": [version_code],
            "status": status,
            "name": name,
            "releaseNotes": [{
                "language": "en-US",
                "text": notes,
            }],
        }],
    }, handle)
PY

track_json="$tmpdir/track.json"
request PUT "${api_base}/edits/${edit_id}/tracks/${track_name}" "$track_json" \
  -H "Content-Type: application/json" \
  --data-binary "@${track_body}"
echo "Assigned versionCode ${version_code} to Play track: ${track_name}"

commit_json="$tmpdir/commit.json"
request POST "${api_base}/edits/${edit_id}:commit" "$commit_json" \
  -H "Content-Type: application/json"
echo "Committed Play edit ${edit_id}."
