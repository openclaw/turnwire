# Threat model

## Security objective

Accepted text can influence only the text-model prompt and returned text. It
must not become a command, path, URL fetch, model setting, tool call,
environment variable, or policy decision inside Turnwire.

## Trust boundary

Turnwire is a local stdio MCP server. It does not authenticate callers, open a
network listener, or provide a tunnel. A deployment that crosses hosts must use
an operator-selected transport that supplies the required authentication,
authorization, confidentiality, and integrity.

Trusted components:

- The Turnwire binary and its per-user configuration.
- The operating system account and filesystem implementation protecting state.
- The selected transport and its identity and authorization policy.

Untrusted components:

- Every incoming message.
- Every model reply.
- The configured model endpoint.
- Instructions embedded in either direction.

The host administrator and storage administrator remain outside Turnwire's
guarantees.

## Enforced boundaries

- One synchronous MCP tool: `talk`.
- Valid UTF-8 text only; NUL and empty messages rejected.
- Fixed request and reply byte limits and request timeout.
- A fixed cumulative audit byte quota checked before every append; exhaustion
  performs no write and leaves the verified log inspectable.
- Bounded, strictly validated MCP frames before SDK JSON decoding.
- Bounded nonblocking admission and duplicate coalescing; excess calls receive
  `busy`.
- A lifetime budget of 16 inbound non-call messages bounds notification and
  response queueing; exhaustion closes the session and requires reconnecting.
- No caller-controlled model, endpoint, system prompt, role, tools, paths, or
  headers.
- Model requests contain no tools and follow no redirects.
- Responses API requests disable provider-side response storage.
- Local endpoint by default; remote HTTPS requires explicit configuration.
- Request recorded and synced before inference; reply recorded and synced
  before returning success.
- Any audit write or sync uncertainty poisons the live handle. Retries are not
  served from that handle until close, secure reopen, file and directory sync,
  and complete chain verification succeed.
- Duplicate request IDs with identical text and conversation ID return the
  committed reply; either field conflicting is rejected.
- Detected audit-chain corruption prevents startup.
- An exclusive file lock prevents cooperating Turnwire processes from writing
  the same log.
- Config and audit storage are validated through opened descriptors for owner,
  mode, type, and extended ACL; audit and config entries use no-follow,
  directory-relative opens to reduce path-swap risk.
- Audit-directory ancestors must be root- or current-user-owned and not
  writable by unprivileged users. Sticky temporary directories are allowed
  only with owner-based replacement protection; ambiguous or granting ancestor
  ACLs fail closed.
- Config writes use the same ancestor walk before create or replacement. The
  audit-collision check and the write share one held final-parent descriptor.
- MCP-facing errors use fixed public messages; backend details stay on the
  local diagnostic stream.

Filesystem ordering and persistence claims assume the operating system,
filesystem, and storage device honor their documented file-locking, atomic
rename, and `fsync` semantics.

## Known limitations

- Turnwire does not authenticate or authorize MCP callers. That is the selected
  transport's responsibility.
- Model classifiers cannot prove that text contains no confidential data.
- Text intentionally sent through the tool has crossed the deployment's trust
  boundary.
- A host administrator can replace the binary, configuration, model, and log.
- A hash-chained local file can expose many modifications but not whole-log
  replacement or truncation unless its head is independently checkpointed.
- Hash chaining is not non-repudiation and does not establish who authored a
  message.
- Availability depends on the transport, model endpoint, disk, and host.
- Audit retention and archival are operator responsibilities; Turnwire refuses
  new entries at the configured quota rather than deleting history.
- Windows runtime is intentionally unsupported until owner-only audit DACLs can
  be enforced; the service fails closed instead of storing plaintext broadly.
- macOS ACL inspection uses the native ACL API through cgo. A cgo-disabled
  macOS build fails closed when it reaches secured config or audit storage.
- `doctor --probe` sends one fixed operational prompt directly to the provider,
  discards its reply, and does not append a relay exchange.

## Explicitly excluded from version 1

- Authentication, authorization, or network tunneling.
- File or attachment transfer.
- Shell or subprocess commands derived from messages.
- Browser or computer control.
- URL retrieval or rendered remote media.
- Model tools, MCP sampling, resources, prompts, or server-initiated actions.
- Persistent model conversation history.
- Public HTTP listeners.
