# Threat model

## Objective

Provide a narrow, policy-gated and auditable text channel between two
operator-owned environments through OpenAI, without general host access.
Prevent unauthorized peers, altered messages, unguarded releases, replay
substitution, model/tool escalation, and unaudited delivery claims.

The achievable promise is risk reduction and evidence—not proof that no
confidential information can ever be misclassified or intentionally sent.

## Trust domains

Trusted per endpoint:

- Turnwire binary, fixed guard instruction, local policy, peer-key config.
- Endpoint Ed25519 private key and owner-only state.
- OS account, filesystem durability, and system clock.
- Secure MCP Tunnel/custom-app association and OpenAI authorization policy.
- Operator approval made locally outside MCP.

Untrusted:

- All message text and instructions embedded in it.
- MCP callers and agent-generated envelope JSON until validated.
- Model verdict content until strict decoding and local validation.
- Model endpoint beyond its documented confidentiality/availability contract.
- Envelopes, acknowledgements, timestamps, and claimed audit heads until peer
  signature and bounds checks succeed.

Host/storage administrators can replace binary, keys, config, approvals, or
history. External signed audit-head anchoring is required to detect later
whole-log replacement or truncation.

## Release path

Outbound:

1. Validate size, UTF-8, IDs, configured destination, idempotency, capacity.
2. Append and sync exact proposal.
3. Run local deterministic credential/secret checks. A deterministic denial
   never reaches OpenAI and cannot be locally approved.
4. Call GPT guard with fixed instructions, no tools, `store: false`,
   `background: false`, strict Structured Outputs, policy, peers, direction.
5. Append and sync verdict, model, policy version, OpenAI response ID and
   request ID. Errors and invalid output fail closed.
6. `review` requires exact-body local approval, then a fresh guard call.
7. Sign envelope with identities, IDs, time, body/hash, policy/model verdict,
   and source audit checkpoint.
8. Append and sync exact envelope before returning it.

Inbound repeats the decision. It verifies peer, signature, destination, body
hash, age, audit-head shape, and replay binding before logging plaintext or
calling GPT. Only then can it commit inbox text. The receiver signs the exact
accepted-entry audit head, appends the resulting receipt, and returns it. The
source independently verifies and logs that acknowledgement.

## Enforced boundaries

- Five fixed text-mailbox/audit tools; no resources, prompts, files, shell,
  browser, URLs, attachments, model tools, or caller-selected model/policy.
- Ed25519 peer authentication and message/ack integrity.
- Destination binding and age checks.
- Message IDs permanently bind to first verified envelope hash; request IDs
  bind destination, conversation, and exact text.
- Deterministic secret denial before remote classification.
- Outbound and inbound GPT guards. `allow` required unless exact `review` has a
  local hash-bound approval.
- MCP cannot create approval records.
- Errors, timeouts, malformed JSON, extra fields, oversized responses,
  redirects, unknown peers, and audit uncertainty fail closed.
- Remote guard traffic restricted to the official OpenAI Responses endpoint;
  only literal loopback endpoints allowed for testing.
- Exact size limits, bounded concurrency/MCP frames, fixed audit quota.
- Synced canonical hash-chain events before externally visible transitions.
- Signed checkpoints for independent anchoring.
- Public MCP errors omit provider URLs, env names, paths, backend details.

## OpenAI boundary

Turnwire does not hide plaintext from OpenAI. The calling agent may already hold
the message, and GPT guard receives all text not locally denied. Use org data
controls and a policy appropriate for both facts.

`store: false` disables Responses application-state storage for the request; it
is not Zero Data Retention. Default abuse-monitoring retention may still apply.
Current OpenAI docs state GPT-5.5 requires 24-hour extended prompt caching.
Turnwire defaults to GPT-5.4 with `in_memory` and recommends a dedicated
ZDR-approved project.

Secure MCP Tunnel is outbound transport. It does not provide arbitrary host
reach. Its path does not emit individual transport requests as ChatGPT
Compliance Platform events. Platform Audit logs cover tunnel metadata changes;
normal custom-app invocation/auth logging applies separately. These records aid
reconciliation but are not a mirrored Turnwire ledger.

## Known limitations

- GPT and deterministic classifiers can miss confidential data or false
  positive. Models are not proof-producing DLP systems.
- A caller authorized for the source custom app can propose messages. Stdio
  does not expose verified individual human identity, so audit identifies
  configured endpoint and peer.
- The agent carries envelope JSON. Turnwire does not directly connect hosts.
- Work-to-personal app association can violate policy even when Turnwire works.
  Administrative approval is external.
- Plaintext remains in owner-only audit and pending files. Disk encryption,
  backup controls, retention, and secure deletion are deployment duties.
- A compromised endpoint/key can sign malicious envelopes. Key revocation is
  currently manual peer removal/config replacement.
- Checkpoints prove endpoint-key possession, not uncompromised host or human
  authorship.
- Availability depends on OpenAI, tunnel, guard API, clocks, disk, endpoints.
- Windows fails closed until owner-only DACL validation exists.

## Deployment requirements

- Dedicated OS account and full-disk encryption per endpoint.
- Dedicated OpenAI API project; ZDR where eligible; no API-key sharing.
- One tunnel/custom app per endpoint with least-privilege workspace association.
- Operator-reviewed policy and explicit peer keys.
- Process manager for `tunnel-client`; no public Turnwire listener.
- Periodic checkpoint storage in both administrative domains.
- Reconcile release, acceptance, acknowledgement, local heads, guard request
  IDs, and available OpenAI logs.
- Document key rotation, peer removal, archival, incident response, revocation.
