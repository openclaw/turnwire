# Configuration

Turnwire reads one owner-only JSON file. It never loads repository config or
`.env` files.

Default locations:

- macOS config: `~/Library/Application Support/turnwire/config.json`
- macOS state: `~/Library/Application Support/turnwire/`
- Linux config: `${XDG_CONFIG_HOME:-~/.config}/turnwire/config.json`
- Linux state: `${XDG_STATE_HOME:-~/.local/state}/turnwire/`

Global `--config PATH` and `--data-dir PATH` overrides precede the command.

## Complete shape

```json
{
  "identity": {
    "name": "work",
    "peers": [
      {
        "name": "personal",
        "public_key": "RAW_BASE64_ED25519_PUBLIC_KEY"
      }
    ]
  },
  "deployment": {
    "id": "turnwire-work"
  },
  "guard": {
    "api": "responses",
    "endpoint": "https://api.openai.com/v1/responses",
    "model": "gpt-5.4-2026-03-05",
    "api_key_env": "OPENAI_API_KEY",
    "allow_remote": true,
    "policy_version": "turnwire-default-v1",
    "policy": "Allow only low-sensitivity coordination text...",
    "prompt_cache_retention": "in_memory"
  },
  "limits": {
    "max_message_bytes": 16384,
    "max_audit_bytes": 268435456,
    "timeout": "120s",
    "max_message_age": "24h",
    "max_concurrent": 1,
    "max_requests_per_minute": 60,
    "max_guard_calls_per_hour": 120
  },
  "audit_dir": "/optional/absolute/owner-only/path"
}
```

Unknown fields rejected.

## Identity and peers

`identity.name` is the signed endpoint address. `turnwire init` generates
`identity.ed25519` inside owner-only state. The private key never appears in
config or CLI output. `turnwire identity show` prints only the public key.

Each peer binds an allowed name to a raw-base64 Ed25519 public key. Duplicate
names, self-peers, malformed keys, and unconfigured destinations fail closed.
Add peers with `turnwire peer add NAME PUBLIC_KEY`.

`turnwire identity rotate --force --output PATH` writes a transition signed by
both old and new keys, then replaces the local key. Transfer that JSON out of
band and run `turnwire peer rotate NAME ROTATION_FILE` on every peer. `turnwire identity
revoke --force --output PATH` writes a signed certificate/checkpoint bundle and
destroys the local key;
remove the peer pin with `turnwire peer remove --force NAME`.

Changing the identity name while reusing a private key changes the signed
logical identity. Treat that as key management; update both peers explicitly.

## Deployment identity

`deployment.id` is the operator-declared tunnel/custom-app identity. It enters
every startup attestation and signed checkpoint. Set it to a stable deployment
identifier that matches the OpenAI-side tunnel/app inventory; it is evidence,
not a remote proof that OpenAI associated the correct tunnel.

## Guard

Only non-streaming Responses accepted. Remote traffic is restricted to exactly
`https://api.openai.com/v1/responses`; alternate HTTPS hosts, ports, query
strings, and fragments rejected. HTTP allowed only for literal loopback IPs for
testing. Redirects and ambient proxies disabled.

Every eligible outbound and valid inbound message is untrusted JSON beneath a
fixed classifier instruction. Requests set:

```json
{
  "store": false,
  "background": false,
  "tools": [],
  "text": {
    "format": {
      "type": "json_schema",
      "strict": true
    }
  }
}
```

The model selects one classification from a closed enum. Turnwire maps that
single value to a consistent `allow`, `review`, or `deny` verdict. The response
must identify the exact configured model snapshot and include both OpenAI
response and request IDs. Invalid output, a different returned model, missing
evidence, HTTP failure, missing credentials, cancellation, and timeout produce
no envelope. Deterministic secret rules can deny before the API call.

Default: pinned GPT-5.4 with `in_memory` cache retention. Current OpenAI
requirements reject `in_memory` for GPT-5.5; use `24h` or omit it. Init selects
`24h` for GPT-5.5. Prefer GPT-5.4 in a dedicated Zero Data Retention project
when lower cache retention matters. Only `gpt-5.4-2026-03-05` and
`gpt-5.5-2026-04-23` are accepted; floating aliases are rejected.

`api_key_env` names an existing environment variable. Its value is never
written or logged. `policy` enters every verdict; increment `policy_version`
whenever its meaning changes. Callers cannot select model or policy.

## Local approval

A `review` creates an immutable pending record beneath owner-only `approvals`.
`turnwire approve MESSAGE_ID` displays exact direction, peers, body hash, and
body, then requires local confirmation. Approval binds to the exact SHA-256
body. MCP has no approval tool.

Retrying reruns deterministic and model guards. Approval can override only
`review`, never `deny` or a guard failure.

## Limits

- `max_message_bytes`: exact UTF-8 body; maximum 1 MiB.
- `max_audit_bytes`: encoded audit quota; default 256 MiB, maximum 512 MiB.
- `timeout`: one model guard call.
- `max_message_age`: accepted envelope/acknowledgement age.
- `max_concurrent`: guard operations; default 1, maximum 8.
- `max_requests_per_minute`: all MCP tool operations; default 60, maximum 600.
- `max_guard_calls_per_hour`: combined outbound and inbound model calls;
  default 120, maximum 1000.

Budgets are fixed-window counters persisted and fsynced before admission. They
survive restart; clock rollback does not replenish them. Corrupt or unwritable
accounting fails closed. MCP additionally rejects JSON-RPC batches, emits only
structured tool results, caps each output frame, and stops `list_messages`
before its encoded result exceeds the fixed protocol ceiling.

Empty/invalid text, NUL, expired or future records, wrong destinations, unknown
peers, bad signatures, body-hash mismatches, replay conflicts, and over-limit
data fail closed.

## Storage

Config, state, identity keys, approvals, budget counters, `audit.key`, and
`audit.jsonl` must be current-user
owned without group/other access or granting ACLs. Final symlinks rejected.
Components traversed through held, no-follow descriptors. Audit text is
AES-256-GCM encrypted before it enters `audit.jsonl`; hashes and metadata remain
available for verification. The key is a separate owner-only state file, not a
substitute for full-disk encryption or a hardware-backed secret store. Audit
entries are appended and synced before release, acceptance, or acknowledgement
returns.

The log is append-only and SHA-256 hash chained; deleting or truncating it would
also remove replay and delivery state. Do not rotate it destructively. Export
redacted signed metadata periodically, retain the full encrypted state for the
endpoint's lifetime, monitor quota, and decommission into a new identity/state
directory before exhaustion. See the deployment runbook.
