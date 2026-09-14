# Changelog

## Unreleased

## 0.1.4 - 2026-09-13

**Highlights:** Accepted inboxes survive local identity rotation, and send/receive results persist across restarts.

- Recover accepted inboxes after local identity rotation and refresh delivery receipts with the current key while preserving their original acceptance proof.
- Preserve complete send and receive results across restarts, including reason codes for approved reviews and older audit logs.
- Reject malformed local approval records consistently, including trailing JSON, invalid text encoding, and unknown fields on retries.
- Honor explicit empty and false init flags, including cache retention and remote-access policy, and reject explicitly empty required settings.
- Apply the log-show display budget to audit details as well as message text, matching log-list accounting.
- Compatibility: source builds now require Go 1.26 to use current Go support libraries after Go 1.25 left upstream support; release binaries retain macOS 12 compatibility.

## 0.1.3 - 2026-09-11

**Highlights:** Reliable guard configuration across peer updates and bounded guard requests.

- Preserve explicit empty and false guard settings during config rewrites, including peer updates, so saved settings do not revert to defaults or invalidate GPT-5.5 configurations.
- Bound default OpenAI guard requests while honoring configured call timeouts, and avoid a panic when DefaultTransport is not *http.Transport, thanks @SebTardif.
- Refresh Go tooling, SBOM generation, and release attestations; test Go 1.25, 1.26, and 1.27 while retaining Go 1.25 source support and macOS 12 release compatibility.

## 0.1.2 - 2026-08-02

- Bound MCP shutdown so a stuck worker cannot hang process exit, thanks @SebTardif.
- Rewrite the README with clearer installation, setup, security, and operations guidance.
- Refresh the release attestation action and Go tooling dependencies.

## 0.1.1 - 2026-08-01

- Update the MCP Go SDK to 1.7.0 with protocol 2026-07-28 compatibility.
- Treat closed stdout pipes as clean CLI pipeline completion, thanks @SebTardif.

## 0.1.0 - 2026-07-27

- Initial release of Turnwire as a signed peer mailbox with outbound and inbound GPT-5.4/GPT-5.5 guards, deterministic secret blocking, local hash-bound approvals, delivery acknowledgements, and bilateral audit receipts.
- Add Ed25519 endpoint identities, trusted-peer configuration, OpenAI request evidence, signed audit checkpoints, and practical Secure MCP Tunnel deployment guidance.
- Harden the channel with exact returned-model pinning, single-classification verdicts, request and model-call budgets, structured-only byte-bounded MCP output, and JSON-RPC batch rejection.
- Encrypt audit text at rest, persist fail-closed request/model budgets across restarts, bind measured deployments into signed checkpoints, and add dual-signed identity rotation, revocation, peer removal, and redacted audit exports.
- Add hardened systemd/launchd tunnel service examples and a tag-only release pipeline producing checksummed archives, CycloneDX SBOMs, and GitHub build-provenance attestations.
