# Development

Turnwire uses Go 1.26 or newer. Run `go test -race ./...`, `go vet ./...`, and
`go build ./cmd/turnwire` before proposing a change. Keep Go source formatted
with `gofmt`. Run `python3 -I scripts/smoke.py ./turnwire` to exercise the built
CLI and two MCP endpoints against a synthetic loopback guard without credentials.
CI runs this proof on macOS and Linux with both supported Go series.

Use the latest patch release of a supported Go series. CI also checks reachable
vulnerabilities on Linux for both series with
`go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...`.
CI pins Go 1.26.9 and 1.27.2 so a preinstalled runner toolchain cannot silently
select an older, vulnerable patch. Linux release builds use Go 1.27.2; macOS
releases use Go 1.26.9 to retain macOS 12 support.
All macOS jobs use Apple Silicon `xcode-27` runners. The amd64 release checks
cross-compile and execute the built CLI under Rosetta, after verifying that
`arch -x86_64 /usr/bin/true` succeeds.

Live OpenAI tests are opt-in through `TURNWIRE_LIVE_OPENAI=1` and
`OPENAI_API_KEY`; they incur API usage and use fixed synthetic text.

## macOS release builds

macOS release binaries support macOS 12 and newer. Build them with Go 1.26
and cgo enabled: the owner-only storage checks call Apple's ACL APIs, and
builds without cgo reject storage operations. Source builds with newer Go
versions also inherit that Go version's minimum supported OS.

On macOS, use the same compiler/linker settings and artifact gate as CI:

```bash
source scripts/macos-release-env.sh
go build -trimpath -ldflags "-s -w" -o turnwire ./cmd/turnwire
python3 -I scripts/check_macos_target.py ./turnwire
python3 -I scripts/smoke.py ./turnwire
```

The environment pins the deployment target for cgo compilation and external
linking. The gate checks every Mach-O deployment command against macOS 12.0
and rejects missing targets; an SDK or runner upgrade must not silently raise
the minimum. CI builds and exercises both release architectures with Go 1.26,
and the release workflow checks the actual binary before archiving or attesting it.

## Releasing

Prepare a release PR with a dated version section in `CHANGELOG.md`, a one-line
`**Highlights:**` summary, and every unreleased bullet preserved. Leave an empty
`Unreleased` section above it. Use a patch version for fixes, dependencies, and
security changes; use a minor version for new product functionality. Merge only
after review and CI pass on the exact PR head.

Create a signed annotated `vVERSION` tag on the merged commit and push it.
`.github/workflows/release.yml` builds Linux amd64/arm64 and macOS amd64/arm64
archives with SBOMs, checksums, and GitHub build attestations. Its macOS jobs
validate the deployment target, sign with the OpenClaw Foundation Developer ID,
and notarize before archiving or attesting. The CI-only signing script uses an
ephemeral keychain and requires repository secrets `MACOS_SIGNING_P12`,
`MACOS_SIGNING_P12_PASSWORD`, `ASC_KEY_ID`, `ASC_ISSUER_ID`, and
`ASC_PRIVATE_KEY_P8`. Check `notarytool history` before tagging. For local signing,
use the shared release-mac-app helper rather than the CI-only script.

Verify the published release body matches its changelog section, download all
five assets, verify checksums and attestations, and smoke-test the downloaded
binary. On both macOS binaries check the deployment target, strict code signature,
and online notarization ticket (`codesign --verify --strict --check-notarization
-R=notarized BINARY`); standalone Mach-O files do not support stapled tickets.
Confirm the Go module version resolves through `proxy.golang.org`. Turnwire has
no npm, Homebrew, or Sparkle publication channel. Never replace an existing tag.

If packaging fails before publication, repair the workflow on `main`, then run
`gh workflow run release.yml --ref main -f tag=vVERSION`. This rebuilds the
unchanged tagged source with the repaired workflow and signing script. Release
notes still come from the tag; binary version metadata records the tag's commit.
The attestation identifies the recovery workflow revision. Use this only while
the GitHub release is absent; published artifacts must not be replaced.

To validate the current branch without publishing or creating tags, run:

```bash
gh workflow run release.yml --ref main -f tag=vVERSION -f dry_run=true
```

Use the current version for `vVERSION`. Dry runs build the selected workflow
revision instead of checking out the tag, sign and notarize the macOS archives,
run their deployment-target and synthetic smoke checks, and upload workflow
artifacts. They skip attestations and GitHub release publication.

## Code boundaries

- `cmd/turnwire` owns process signals and exit codes; `internal/cli` routes
  commands into initialization, serving, doctor, identity, peers, approval,
  and log operations.
- `internal/mailbox` owns signed send, receive, confirmation, inbox, and
  checkpoint operations. `evaluation.go` combines deterministic and model
  decisions; `replay.go` rebuilds durable message state. `service.go` owns
  construction, admission, locking, and shutdown.
- `internal/mcpserver` translates the five mailbox tools into MCP and enforces
  byte, frame, concurrency, and output limits below SDK dispatch.
- `internal/guard` owns secret scanning, Responses requests, and the mapping
  from one model classification to a consistent policy verdict.
- `internal/audit` owns append durability and handle lifecycle in `audit.go`,
  encryption and canonical hashes in `entry.go`, verified traversal in
  `scan.go`, and descriptor-bound path checks in `paths.go`.
- `internal/owneronly` validates ownership, permissions, ACLs, and path
  traversal. `internal/securestore` uses those descriptors for bounded state
  files; `internal/budget` persists admission counters and `internal/approval`
  stores exact local approval bindings.
- `internal/config`, `internal/identity`, `internal/attestation`, and
  `internal/buildinfo` own configuration, signing/key lifecycle, deployment
  measurements, and embedded build metadata, respectively.
- `internal/identifier` and `internal/strictjson` define shared identifier and
  lossless text checks. `internal/testutil` contains test fixtures only.

## Compatibility and proof

Unsigned JSON field order, audit canonicalization, and signed metadata are
protocol contracts. Preserve them when reorganizing code. Storage checks must
remain descriptor-relative, and a write/sync failure must never be treated as
a successful release or receipt.

Test both the live state transition and reconstruction after restart when
changing mailbox state. Exercise a built CLI through MCP for integration
proof. Use a literal loopback guard endpoint for synthetic local tests, and
keep private state and API credentials out of fixtures and proof output.
