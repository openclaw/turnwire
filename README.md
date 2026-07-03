# Turnwire

[![CI](https://github.com/openclaw/turnwire/actions/workflows/ci.yml/badge.svg)](https://github.com/openclaw/turnwire/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Turnwire is an audited, text-only MCP relay. A caller sends text through one
`talk` tool, a configured language model produces text, and Turnwire records
both messages before returning the reply.

Turnwire exposes exactly one capability:

```text
talk(text, request_id?, conversation_id?) -> reply + audit receipt
```

It does not expose files, shell commands, browser control, URLs, MCP resources,
MCP prompts, or model tools. Conversation IDs correlate messages but do not add
model-side memory in version 1.

## Architecture

```text
MCP client or agent
    │ MCP request and response
    ▼
operator-selected transport
    │ authenticated externally when crossing hosts
    ▼
turnwire serve ──► Chat Completions-compatible text model
    │
    └── append-only audit.jsonl
```

Turnwire serves MCP over stdin and stdout. It does not open a network listener,
authenticate callers, or establish a tunnel. When the client and Turnwire run
on different hosts, place it behind an authenticated transport appropriate for
your environment.

## Quick start

Requirements:

- macOS or Linux. Windows builds, but runtime audit storage intentionally fails
  closed until owner-only DACL enforcement is implemented.
- macOS builds must have cgo enabled so native ACLs can be inspected; a
  cgo-disabled binary compiles but fails closed at runtime.
- Go 1.25 or newer.
- A non-streaming Chat Completions-compatible endpoint. The default is
  [Ollama](https://ollama.com/) serving the public
  [`gpt-oss:20b`](https://ollama.com/library/gpt-oss) model on loopback.

```bash
mkdir -p ./bin
go build -o ./bin/turnwire ./cmd/turnwire
ollama pull gpt-oss:20b
./bin/turnwire init
./bin/turnwire doctor --probe
```

`init` writes a restrictive per-user JSON configuration and creates the audit
directory. It never writes an API key. Configure your MCP client to start the
absolute binary path with the `serve` argument. For clients that use the common
JSON MCP server shape:

```json
{
  "mcpServers": {
    "turnwire": {
      "command": "/absolute/path/to/turnwire/bin/turnwire",
      "args": ["serve"]
    }
  }
}
```

The exact outer configuration format depends on the client.

The process writes MCP JSON-RPC only to stdout. Diagnostics go to stderr;
message content goes to the audit log. To keep non-call SDK queueing bounded,
each stdio session fails closed after 16 inbound notifications or responses;
reconnect to start a fresh session.

### Optional: OpenAI Secure MCP Tunnel

[OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
is one optional public transport integration. Its public
[`tunnel-client`](https://github.com/openai/tunnel-client) can start Turnwire as
a local stdio MCP server:

```bash
tunnel-client init \
  --sample sample_mcp_stdio_local \
  --profile turnwire \
  --tunnel-id TUNNEL_ID \
  --mcp-command "/absolute/path/to/turnwire/bin/turnwire serve"

tunnel-client doctor --profile turnwire --explain
tunnel-client run --profile turnwire
```

Follow the public guide for tunnel creation, permissions, and workspace
association. The tunnel is not part of Turnwire and other authenticated
transports may be used instead.

## CLI

```text
turnwire init [options]       Create config and audit storage
turnwire serve                Serve MCP over stdin/stdout
turnwire doctor [--probe]     Validate config, storage, and model access
turnwire log list             List logged exchanges
turnwire log show ID          Show one exchange
turnwire log verify           Verify the complete audit hash chain
turnwire version              Print build information
```

Human-readable log commands escape terminal controls. `log list` retains only
exchange metadata, while `log list --json` includes exact logged UTF-8 bodies.
Both modes enforce a 16 MiB in-memory budget for the selected newest records;
older history is verified without being retained. Reduce `--limit` or filter
with `--conversation` if the selected window exceeds the budget. JSON records
are emitted one at a time after the complete audit chain has been verified.

## Configuration

The default config is local-only:

```json
{
  "version": 1,
  "provider": {
    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
    "model": "gpt-oss:20b"
  },
  "limits": {
    "max_input_bytes": 16384,
    "max_output_bytes": 16384,
    "max_audit_bytes": 268435456,
    "timeout": "120s",
    "max_concurrent": 1
  }
}
```

Remote providers require HTTPS and an explicit `allow_remote` opt-in. If a
provider needs a bearer token, set `api_key_env` to the *name* of an environment
variable; never put the value in the config file or a command-line flag. See
[configuration](docs/configuration.md).

## Audit behavior

Each accepted request is written and synced before model execution. Each reply
is written and synced before success is returned. This ordering depends on the
operating system, filesystem, and storage device honoring their documented
`fsync` semantics; it is not a guarantee against faulty or malicious storage.

Entries contain exact UTF-8 content, SHA-256 content digests, a monotonic
sequence, and a hash link to the previous entry. The service refuses to start
if verification detects a malformed or modified chain, and an exclusive file
lock prevents cooperating Turnwire processes from writing the same log.

The audit path is opened through validated directory descriptors. A failed or
uncertain append or sync poisons that live handle: no reply lookup or log read
is allowed until close and a successful synced, verified reopen. Standalone log
commands require the exclusive recovery lock and therefore refuse to read
while a Turnwire writer is live. Request IDs remain usable across restarts by
scanning the verified log. Active requests and compact idempotency metadata
stay in memory; completed reply bodies are read and verified on demand from
their indexed audit offsets.

The encoded log is capped at 256 MiB by default. Entries are admitted against
the exact serialized size before any write; quota exhaustion is a clean error
that does not poison verification or log inspection. Turnwire never deletes or
rotates audit history automatically. Archive or replace the log under your own
retention policy while the service is stopped. To resume after exhaustion,
preserve the old directory and its final audit head, then point `audit_dir` at
a fresh absolute owner-only directory (or archive the old directory and
recreate the configured path) before restarting.

`doctor --probe` is the sole operational exception: it sends fixed,
non-user-supplied health-check text to the provider, discards the model text,
and records no relay exchange.

The local hash chain can detect many modifications but cannot prevent a host
administrator from replacing or truncating the entire log. Independently
checkpoint or sign audit heads if that threat matters to your deployment.

## Development

```bash
go test -race ./...
go vet ./...
go build ./cmd/turnwire
```

Ordinary Go builds populate `turnwire version --json` from the module and VCS
metadata embedded by the Go toolchain, including whether the working tree was
modified. When VCS state is unavailable, the JSON omits `modified` instead of
claiming the source tree was clean. Release builds can supply authoritative
values with linker flags. Keep Go's VCS stamping enabled so a dirty release
checkout remains visible; release automation should also require a clean tree.
Using the source revision time instead of the wall-clock build time keeps the
provenance fields stable for identical release inputs:

```bash
VERSION=v1.2.3
REVISION="$(git rev-parse HEAD)"
REVISION_TIME="$(git show -s --format=%cI HEAD)"
go build -trimpath \
  -ldflags="-X github.com/openclaw/turnwire/internal/buildinfo.Version=${VERSION} -X github.com/openclaw/turnwire/internal/buildinfo.Commit=${REVISION} -X github.com/openclaw/turnwire/internal/buildinfo.BuildTime=${REVISION_TIME}" \
  -o ./bin/turnwire ./cmd/turnwire
```

Read the [threat model](docs/threat-model.md) before broadening the protocol.
File access, tool execution, attachment transfer, and unsolicited network
capabilities are intentionally out of scope for version 1.

## License

Turnwire is available under the [MIT License](LICENSE).
