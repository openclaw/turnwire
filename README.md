# Turnwire 🔐 — Text crosses. Trust doesn't.

[![CI](https://img.shields.io/github/actions/workflow/status/openclaw/turnwire/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/openclaw/turnwire/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/openclaw/turnwire?style=flat-square)](https://github.com/openclaw/turnwire/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat-square)](https://go.dev/)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey?style=flat-square)](#requirements)
[![License](https://img.shields.io/github/license/openclaw/turnwire?style=flat-square)](LICENSE)

Turnwire is a signed, policy-guarded MCP channel for moving text between two private environments. Each environment runs a local endpoint that checks, signs, and audits messages without exposing an inbound network service.

```text
source endpoint                         destination endpoint
send_message ── signed envelope ──────▶ receive_message
confirm_delivery ◀── signed receipt ───
```

The agent transports released JSON between two independently configured endpoints. Turnwire exposes no file, shell, browser, URL-fetch, resource, prompt, or model tools.

## Install

Install from source:

```bash
go install github.com/openclaw/turnwire/cmd/turnwire@latest
```

[GitHub Releases](https://github.com/openclaw/turnwire/releases/latest) also provide checksummed macOS and Linux archives with SBOMs and build attestations. Follow the [release verification steps](docs/deployment.md#install-and-verify) before placing a downloaded binary on your `PATH`.

### Requirements

- macOS or Linux
- Go 1.25 or newer when building from source
- An OpenAI API key for guard checks

Windows builds compile, but runtime storage checks fail closed until owner-only DACL enforcement is available.

## Quick start

Create a disposable local endpoint and print its public identity:

```bash
demo_dir="$(mktemp -d)"
turnwire --config "$demo_dir/config.json" --data-dir "$demo_dir/state" \
  init --identity work --deployment-id turnwire-work
turnwire --config "$demo_dir/config.json" --data-dir "$demo_dir/state" identity show
```

This creates a local signing key, configuration, and encrypted audit chain. It does not call the guard API; pairing and message transfer require a second endpoint.

## Pair two endpoints

Initialize each endpoint with a stable, distinct identity and deployment ID. Exchange only the public keys printed by `turnwire identity show`, then pin the other endpoint with `turnwire peer add NAME PUBLIC_KEY`.

Set `OPENAI_API_KEY` on both machines and run `turnwire doctor --probe`. The probe checks local storage, identity and peer configuration, audit integrity, and guard access using fixed non-user text.

The [configuration reference](docs/configuration.md) documents paths, guard policy, supported model snapshots, limits, local approval, and storage requirements.

## Connect an MCP client

Turnwire serves MCP over stdio:

```json
{
  "mcpServers": {
    "turnwire-work": {
      "command": "/absolute/path/to/turnwire",
      "args": ["serve"]
    }
  }
}
```

For hosted clients, run one outbound Secure MCP Tunnel per endpoint. The [deployment and operations runbook](docs/deployment.md) covers tunnel setup, supervision, audit retention, key rotation, and the kill switch.

## Message flow

1. `send_message` runs deterministic secret checks and a pinned OpenAI guard. An `allow` verdict releases a peer-addressed Ed25519-signed envelope; `review` requires a hash-bound local CLI approval.
2. The agent carries the envelope to the configured peer's `receive_message` tool.
3. The peer verifies the destination, signature, body hash, age, and replay binding, then runs its own deterministic and model guards before committing the message.
4. The peer signs an acknowledgement over the accepted audit head. The source verifies and records it through `confirm_delivery`.

Turnwire does not connect the hosts directly. Secure MCP Tunnel supplies outbound transport; the agent carries the released envelope and acknowledgement between endpoints.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `send_message` | Guard text and return a signed envelope for one configured peer |
| `receive_message` | Verify and independently guard an envelope, then commit it to the inbox |
| `confirm_delivery` | Verify and record the receiver's signed acknowledgement |
| `list_messages` | Read accepted inbox messages; every read is audited |
| `audit_checkpoint` | Sign the current local audit-chain head for external retention |

MCP cannot approve a review-required message. The operator must run `turnwire approve MESSAGE_ID` locally, then retry the identical call.

## Security boundaries

- Deterministic rules deny obvious credentials before they reach the guard API.
- Guard calls use strict Structured Outputs, no tools, `store: false`, `background: false`, and exact returned-model matching. Errors fail closed.
- Each endpoint independently guards the same text and trusts only configured peer public keys.
- Sensitive audit fields are AES-GCM-encrypted within a hash-chained local log; signed checkpoints support external reconciliation.
- Turnwire is a narrow channel, not a sandbox or proof-producing DLP system. OpenAI receives text submitted to the model guard, and classifiers can miss confidential data.

Read the full [threat model](docs/threat-model.md) before deployment. It defines the trust domains, enforced boundaries, OpenAI data boundary, known limitations, and required operational controls.

## Operations

Use `turnwire log list`, `turnwire log show`, and `turnwire log verify` for local inspection. `turnwire log export --output PATH` creates redacted reconciliation metadata, while `turnwire checkpoint` prints a signed audit-head checkpoint for independent storage.

Keep the encrypted audit chain for the endpoint's lifetime because it also carries replay and delivery state. The [operations runbook](docs/deployment.md#audit-and-retention) covers retention, reconciliation, identity rotation, revocation, and recovery.

## Development

```bash
go test -race ./...
go vet ./...
go build ./cmd/turnwire
```

## License

MIT. See [LICENSE](LICENSE).
