# Turnwire

[![CI](https://github.com/openclaw/turnwire/actions/workflows/ci.yml/badge.svg)](https://github.com/openclaw/turnwire/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Turnwire is a signed, policy-guarded, text-only channel between two private
environments. Each environment runs its own local endpoint. An agent carries a
released envelope through OpenAI to the other endpoint; Turnwire never opens an
inbound port and never gives OpenAI general host access.

Five MCP tools:

```text
send_message       guard text, sign a peer-addressed envelope
receive_message    verify peer signature, guard again, commit to inbox
confirm_delivery   verify and record the receiver acknowledgement
list_messages      read accepted messages; every read is audited
audit_checkpoint   sign the current local audit-chain head
```

No files, shell, browser, URL fetch, MCP resources/prompts, or model tools.

## Practical flow

```text
work agent / OpenAI                                      personal agent / OpenAI
        |                                                           |
        | Secure MCP Tunnel                         Secure MCP Tunnel|
        v                                                           v
 work Turnwire -- local DLP -- GPT guard      GPT guard -- local DLP -- personal Turnwire
        |                 |                         |                 |
        |          signed envelope -- agent ------->                 |
        |                 <---- signed acknowledgement               |
        v                                                           v
 work audit.jsonl                                       personal audit.jsonl
```

1. `send_message` records the proposal locally, runs deterministic secret/DLP
   checks, then calls the configured GPT guard with strict Structured Outputs.
2. A denial produces no envelope. A review creates a local pending record;
   only `turnwire approve MESSAGE_ID` can approve that exact body hash. MCP
   cannot approve it.
3. Allowed or locally approved text is signed with the source Ed25519 key. The
   agent carries the JSON envelope to the peer's `receive_message` tool.
4. The peer verifies destination, signature, body hash, age, and replay binding,
   then independently repeats deterministic and GPT guards before committing.
5. The peer commits the inbox entry, signs that exact audit head in an
   acknowledgement, then logs receipt issuance. The source verifies and
   records it with `confirm_delivery`.

OpenAI does not “crawl” either machine. The tunnel client makes an outbound
HTTPS connection, and OpenAI can call only the exposed MCP tools. Secure MCP
Tunnel is transport, not generic host-to-host networking.

## Security model

- Default guard: pinned `gpt-5.4-2026-03-05` through Responses.
- GPT-5.5 supported with `--model gpt-5.5-2026-04-23` or `gpt-5.5`.
- Every releasable message gets an outbound model verdict. Every received
  envelope gets a separate inbound verdict. Errors and malformed output fail
  closed.
- Obvious credentials and secrets are denied locally before reaching the guard
  API. GPT is a secondary classifier, not the cryptographic or deterministic
  boundary.
- Guard calls set `store: false`, `background: false`, provide no tools, and
  demand strict JSON Schema output. GPT-5.4 defaults to `in_memory` prompt
  caching. Current OpenAI docs say GPT-5.5 requires 24-hour extended caching,
  so init selects `24h` for GPT-5.5.
- Endpoints trust only configured peer public keys. Envelopes and delivery
  acknowledgements are Ed25519 signed.
- Exact text, decisions, policy/model, OpenAI response and `x-request-id`, peer
  identities, hashes, and receipts enter a synced hash-chained local log.
- Signed audit checkpoints can be independently stored to detect later
  whole-log replacement or truncation.

For strongest OpenAI-side controls, use a dedicated API project approved for
Zero Data Retention. `store: false` alone does not remove default abuse-
monitoring retention. See [Data controls](https://developers.openai.com/api/docs/guides/your-data#v1responses).

Secure MCP Tunnel does not emit individual transport requests as Compliance
Platform app events. Tunnel create/update/delete events appear in Platform
Audit logs; normal custom-app invocation/auth logging applies separately. See
the official [logging boundaries](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels#logging-boundaries).
Turnwire's local ledgers remain the authoritative per-message record.

## Set up two endpoints

Requirements: macOS or Linux, Go 1.25+, and `OPENAI_API_KEY`. Windows runtime
fails closed until owner-only DACL enforcement exists.

Work machine:

```bash
go build -o ./bin/turnwire ./cmd/turnwire
./bin/turnwire init --identity work
./bin/turnwire identity
```

Personal machine:

```bash
go build -o ./bin/turnwire ./cmd/turnwire
./bin/turnwire init --identity personal
./bin/turnwire identity
```

Exchange only the printed public keys, then pin each peer:

```bash
# work machine
./bin/turnwire peer add personal PERSONAL_PUBLIC_KEY

# personal machine
./bin/turnwire peer add work WORK_PUBLIC_KEY
```

Verify both:

```bash
./bin/turnwire doctor --probe
```

GPT-5.5 example:

```bash
./bin/turnwire init --identity work --model gpt-5.5-2026-04-23 --force
```

`--force` preserves the key and audit history but replaces config. Recheck
policy and peers after a forced init.

## Secure MCP Tunnel

Configure a separate tunnel and custom app per endpoint. The public
[`tunnel-client`](https://github.com/openai/tunnel-client) can spawn Turnwire:

```bash
tunnel-client init \
  --sample sample_mcp_stdio_local \
  --profile turnwire-work \
  --tunnel-id TUNNEL_ID \
  --mcp-command "/absolute/path/to/turnwire/bin/turnwire serve"

tunnel-client doctor --profile turnwire-work --explain
tunnel-client run --profile turnwire-work
```

Follow the official [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
for permissions and workspace association. Associate a work endpoint with a
personal workspace only when the work administrator permits that relationship.

Direct local MCP client:

```json
{
  "mcpServers": {
    "turnwire-work": {
      "command": "/absolute/path/to/turnwire/bin/turnwire",
      "args": ["serve"]
    }
  }
}
```

## Review and audit

On `review_required`, approve locally, then retry the identical call:

```bash
turnwire approve MESSAGE_ID
```

Audit commands:

```text
turnwire log list [--type TYPE] [--limit N] [--json]
turnwire log show ID [--json]
turnwire log verify [--json]
turnwire checkpoint
```

Store periodic checkpoints outside the endpoint. Reconcile message IDs, hashes,
signed acknowledgements, model/request IDs, and available OpenAI custom-app
invocation logs.

## Important limits

- If GPT inspects plaintext, OpenAI received it. Turnwire controls transfer
  between environments; it cannot make guard input invisible to OpenAI.
- A classifier cannot prove text non-confidential. Deterministic checks, narrow
  policy, local review, signatures, and evidence reduce risk—not guarantee zero
  leakage.
- Tunnel authorization controls the app path. Stdio does not expose a verified
  individual human caller identity; logs identify endpoint and peer.
- A host administrator can replace binary, keys, policy, approvals, or log.
- The agent carries released envelopes; Turnwire does not directly connect
  hosts.
- Text only. Attachments and arbitrary host access remain out of scope.

Read the [threat model](docs/threat-model.md) and
[configuration reference](docs/configuration.md) before deployment.

## Development

```bash
go test -race ./...
go vet ./...
go build ./cmd/turnwire
```

## License

MIT. See [LICENSE](LICENSE).
