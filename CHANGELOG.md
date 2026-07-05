# Changelog

## Unreleased

- Rebuild Turnwire as a signed peer mailbox with outbound and inbound GPT-5.4/GPT-5.5 guards, deterministic secret blocking, local hash-bound approvals, delivery acknowledgements, and bilateral audit receipts.
- Add Ed25519 endpoint identities, trusted-peer configuration, OpenAI request evidence, signed audit checkpoints, and practical Secure MCP Tunnel deployment guidance.
- Harden the channel with exact returned-model pinning, single-classification verdicts, request and model-call budgets, structured-only byte-bounded MCP output, and JSON-RPC batch rejection.
- Encrypt audit text at rest, persist fail-closed request/model budgets across restarts, bind measured deployments into signed checkpoints, and add dual-signed identity rotation, revocation, peer removal, and redacted audit exports.
- Add hardened systemd/launchd tunnel service examples and a tag-only release pipeline producing checksummed archives, CycloneDX SBOMs, and GitHub build-provenance attestations.
