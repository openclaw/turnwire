# Deployment and operations

## Recommended shape

Run one endpoint per trust domain under a dedicated OS account. Use full-disk
encryption, one dedicated OpenAI API project, one Secure MCP Tunnel/custom app,
one Turnwire identity/state directory, and one narrowly associated workspace.
The tunnel client is the supervised process and spawns `turnwire serve`; no
Turnwire TCP listener or inbound firewall rule exists.

Start with manual envelope relay. Automate only after the work administrator
has approved the personal/work association, OpenAI retention settings are
appropriate for the data class, tunnel `Read`/`Use`/`Manage` roles are split,
and both sides agree on checkpoint/export reconciliation.

## Install and verify

Release archives contain the binary, license, and CycloneDX SBOM. Verify before
installation:

```bash
sha256sum -c checksums.txt
gh attestation verify turnwire_VERSION_OS_ARCH.tar.gz --repo openclaw/turnwire
```

Initialize with a deployment ID that matches the tunnel/app inventory:

```bash
turnwire init --identity work --deployment-id turnwire-work
turnwire identity show
turnwire peer add personal PERSONAL_PUBLIC_KEY
turnwire doctor --probe
turnwire checkpoint > initial-checkpoint.json
```

Store API credentials in the platform secret manager. Do not put secrets in
arguments, the JSON config, service definition, or tunnel profile committed to
source control. Prefer short-lived workload credentials where the OpenAI-side
deployment supports them.

Use `packaging/systemd/turnwire-tunnel.service` or the launchd example as a
starting point. Adjust absolute paths, profile name, OS account, state path,
and secret injection locally. Run `tunnel-client doctor --profile turnwire
--explain` before enabling supervision.

## Audit and retention

The encrypted audit chain is authoritative protocol state, including replay
bindings. Never truncate or delete old entries while retaining the identity.
Monitor `max_audit_bytes`; move to a fresh identity/state directory before the
quota is reached.

At a fixed interval and after configuration, binary, policy, peer, or tunnel
changes:

```bash
turnwire checkpoint > checkpoint.json
turnwire log export --output audit-metadata-$(date -u +%Y%m%dT%H%M%SZ).jsonl
```

Copy both to append-only/WORM storage controlled by the corresponding domain.
The export excludes message text and model explanations, includes selected
reconciliation metadata, and ends with a signed checkpoint. Reconcile the two
endpoint ledgers plus available OpenAI tunnel metadata, app invocation/auth,
and organization audit exports. OpenAI logs complement rather than duplicate
Turnwire's message ledger.

## Key rotation

Stop the tunnel service first; the exclusive audit lock makes concurrent local
maintenance fail.

```bash
turnwire identity rotate --force --output work-rotation.json
```

Move the transition through an independently authenticated path. On every peer:

```bash
turnwire peer rotate work work-rotation.json
turnwire doctor --probe
turnwire checkpoint > post-rotation-checkpoint.json
```

The transition is signed by both old and new keys. Do not resume the tunnel
until every expected peer has updated its pin.

## Kill switch

For suspected disclosure or unauthorized tunnel use:

1. Disable the custom app/tunnel association and revoke its OpenAI runtime
   credential.
2. Stop and disable the local tunnel service.
3. On the opposite endpoint, run `turnwire peer remove --force NAME`.
4. On the affected endpoint, run `turnwire checkpoint` and `turnwire log export
   --output final-audit-metadata.jsonl`; store both externally.
5. Run `turnwire identity revoke --force --output revocation.json`. The output
   bundles the signed revocation with a checkpoint covering its prepared audit
   event. Preserve it, encrypted state, and relevant OpenAI audit records.
6. Rebuild from a reviewed release into a fresh state directory, new identity,
   new tunnel/app, and new runtime credential. Reassociate only after review.

Self-signed revocation is evidence, not remote enforcement. Removing the peer
pin, disabling the OpenAI association, and revoking runtime credentials are the
enforcement steps.
