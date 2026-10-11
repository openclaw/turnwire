#!/bin/bash
# CI-only: use an ephemeral keychain, never the operator's release keychain.
set -euo pipefail
set +x

binary=${1:?usage: notarize-macos.sh BINARY}
: "${MACOS_SIGNING_P12:?missing signing certificate}"
: "${MACOS_SIGNING_P12_PASSWORD:?missing signing certificate password}"
: "${ASC_KEY_ID:?missing notarization key ID}"
: "${ASC_ISSUER_ID:?missing notarization issuer}"
: "${ASC_PRIVATE_KEY_P8:?missing notarization key}"
[[ ${GITHUB_ACTIONS:-} == true && $(uname) == Darwin ]] || {
  echo 'This script requires an ephemeral macOS GitHub Actions runner.' >&2
  exit 1
}

umask 077
work=$(mktemp -d "${RUNNER_TEMP:?}/turnwire-sign.XXXXXX")
keychain="$work/signing.keychain-db"
# shellcheck disable=SC2329 # Invoked by the EXIT trap.
cleanup() {
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

printf '%s' "$MACOS_SIGNING_P12" | base64 --decode > "$work/certificate.p12"
printf '%s' "$ASC_PRIVATE_KEY_P8" > "$work/notary.p8"
password=$(openssl rand -hex 32)
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$work/certificate.p12" -k "$keychain" -P "$MACOS_SIGNING_P12_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
identity=$(security find-identity -v -p codesigning "$keychain" |
  awk '/Developer ID Application: OpenClaw Foundation/ { print $2; exit }')
[[ "$identity" =~ ^[0-9A-Fa-f]{40}$ ]] || { echo 'Expected Developer ID identity missing.' >&2; exit 1; }

xcrun notarytool history --key "$work/notary.p8" --key-id "$ASC_KEY_ID" \
  --issuer "$ASC_ISSUER_ID" --output-format json > "$work/history.json"
codesign --force --timestamp --options runtime --identifier org.openclaw.turnwire \
  --keychain "$keychain" --sign "$identity" "$binary"
codesign --verify --strict "$binary"
ditto -c -k "$binary" "$work/turnwire.zip"
xcrun notarytool submit "$work/turnwire.zip" --key "$work/notary.p8" --key-id "$ASC_KEY_ID" \
  --issuer "$ASC_ISSUER_ID" --no-s3-acceleration --wait --output-format json > "$work/notary.json"
cat "$work/notary.json"
[[ $(jq -r '.status' "$work/notary.json") == Accepted ]] || {
  echo 'Notarization was not accepted.' >&2
  exit 1
}

# Standalone Mach-O files cannot be stapled; verify Apple's online ticket.
for attempt in {1..12}; do
  if codesign --verify --strict --check-notarization -R=notarized "$binary"; then
    exit 0
  fi
  echo "Waiting for notarization ticket ($attempt/12)."
  sleep 10
done
echo 'Notarization ticket did not become available.' >&2
exit 1
