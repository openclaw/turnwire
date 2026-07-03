# Configuration

Turnwire reads one explicit per-user JSON file. It never discovers
configuration from the current repository and never loads `.env` files.

Default locations:

- macOS config: `~/Library/Application Support/turnwire/config.json`
- macOS state: `~/Library/Application Support/turnwire/`
- Linux config: `${XDG_CONFIG_HOME:-~/.config}/turnwire/config.json`
- Linux state: `${XDG_STATE_HOME:-~/.local/state}/turnwire/`
- Windows paths can be derived for cross-platform tooling, but `init`, `serve`,
  and `doctor` fail closed until Turnwire can enforce an owner-only Windows
  DACL for plaintext audit storage.

Use `--config PATH` or `--data-dir PATH` for an explicit override. Global flags
must appear before the command.

## Provider

`provider.api` selects `chat_completions` or `responses`. The local default is
`chat_completions`. `turnwire init --provider openai` selects `responses`,
`https://api.openai.com/v1/responses`, `OPENAI_API_KEY`, and `gpt-5.5`.
Use `--model gpt-5.4` when initializing to select GPT-5.4 instead.

`provider.endpoint` must be an absolute URL. Plain HTTP is allowed only for a
literal loopback IP address such as `127.0.0.1` or `[::1]`; hostnames are never
treated as local after DNS resolution. A non-loopback endpoint requires HTTPS
and `provider.allow_remote: true`.

`provider.api_key_env`, when set, names the environment variable containing a
bearer token. The variable's value is read at request time and is never logged.

The endpoint must implement the selected non-streaming API. Chat Completions
receives exactly two messages: a fixed, text-only system instruction and the
accepted user text. Responses receives the same values as `instructions` and
`input`, with `store: false`. Turnwire never sends tools through either API.

## Limits

- `max_input_bytes`: maximum accepted UTF-8 request size.
- `max_output_bytes`: maximum decoded reply size.
- `max_audit_bytes`: maximum encoded `audit.jsonl` size; default 256 MiB,
  maximum 512 MiB.
- `timeout`: Go duration for one model call, such as `120s`.
- `max_concurrent`: maximum admitted model calls; default `1`, maximum `8`.
  Excess unique calls and excess waiters for an active duplicate fail
  immediately with a retryable `busy` error instead of accumulating an
  unbounded queue.

Limits are measured in bytes, not Unicode code points. Empty text, invalid
UTF-8, NUL, redirects, oversized replies, and malformed provider responses fail
closed. Input and output limits may not exceed 1 MiB each so their escaped audit
records remain within the fixed storage bound.

## Audit directory

Set `audit_dir` to an absolute path to override the default audit directory.
Its spelling must already be lexically clean: redundant `.` or `..` components
and repeated or trailing separators are rejected. All operational validation
and inspection then uses the same descriptor-based traversal as the audit
reader, including when a trusted ancestor symlink target itself contains
`..`; a separate path-based `stat` is not an authorization check. `--data-dir`
overrides are made absolute and cleaned before the fixed `audit` component is
added.
New directories are created with mode `0700` and `audit.jsonl` with `0600` on
Unix. Existing paths must already be equally restrictive and are never
chmodded. Opened directory and file descriptors must be owned by the current
user and have no extended or inherited ACL. Final directory and file symlinks
are rejected, and the fixed audit filename is opened relative to the validated
directory handle.

Every audit-directory ancestor is walked from the filesystem root through
held, no-follow directory descriptors. Ancestors must be owned by root or the
current user. Group- or other-writable ancestors are accepted only when the
sticky bit protects a current-user-owned next component, as with `/private/tmp`
or `/tmp`. Linux ancestor ACLs and macOS ACL allow entries fail closed;
deny-only macOS ACLs are permitted because they do not add mutation rights.
Protected root- or current-user-owned ancestor symlinks may be resolved for
system aliases such as macOS `/var`, but the final audit directory and
`audit.jsonl` must not be symlinks.

Each audit-log open syncs both the file and its held directory before chain
verification, including when both already existed. If an append write or sync
has an uncertain result, that log handle refuses every append, read, scan,
verification, and path lookup until it is closed and securely reopened.
Standalone log reads take the same exclusive file lock and sync both handles,
so they refuse to inspect a live writer.

Before each append, the exact encoded line size is checked against
`max_audit_bytes` under the writer lock. A quota rejection performs no write,
does not poison the handle, and leaves verification and inspection available.
An existing verified log at or above a newly lowered quota remains readable,
but `serve` refuses to start at or above the limit and no new entries are
accepted. Turnwire does not rotate or delete history automatically; stop the
service before applying an operator-defined archival or retention procedure.
To resume, preserve the exhausted directory and its final hash-chain head, then
configure a fresh absolute `audit_dir`; alternatively archive the whole old
directory and recreate the configured path. Do not truncate or replace the
active file while `serve` is running. An archived copy can be verified by a
separate Turnwire invocation configured to select that copy.

These operations rely on the operating system, filesystem, and storage device
honoring their documented locking, atomic rename, and `fsync` semantics. They
do not defend against a malicious host administrator or storage implementation.

Only directories created by `init` receive restrictive permissions. An
existing parent supplied through `--config` is never chmodded; it must be owned
by the current user, have no group or other write permission, and have no
extended ACL. Config creation walks every ancestor from the root through the
same held, validated descriptors used for audit storage, creates missing
components with `mkdirat`, and resolves only protected ancestor symlinks.
Replacement is written, validated, synced, and atomically renamed within the
held final parent directory. During `init`, the audit-collision guard checks
that exact parent descriptor and entry name before the write; the same
descriptor is retained through creation or replacement. Config reads use the
same validated ancestor walk and retain a no-follow final file handle.
