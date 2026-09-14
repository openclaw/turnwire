# Development

Turnwire uses Go 1.26 or newer. Run `go test -race ./...`, `go vet ./...`, and
`go build ./cmd/turnwire` before proposing a change. Keep Go source formatted
with `gofmt`. Run `python3 -I scripts/smoke.py ./turnwire` to exercise the built
CLI and two MCP endpoints against a synthetic loopback guard without credentials.
CI runs this proof on macOS and Linux with both supported Go series.

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
