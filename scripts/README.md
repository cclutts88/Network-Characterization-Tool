# NCT Range Operator Scripts

This directory contains both the current small operator scripts and older
deployment automation retained for compatibility.

## Recommended reset workflow

The authoritative instructions are in
`../docs/AIR_GAPPED_RANGE_QUICKSTART.md`. Follow that guide from the beginning.
This file is a short reference for the scripts and must not replace the required
preflight and acceptance steps.

1. Confirm Docker is available:

   ```bash
   docker version --format 'Server {{.Server.Version}} / API {{.Server.APIVersion}}'
   docker compose version
   ```

2. Confirm the default NCT HTTPS port is free:

   ```bash
   ss -ltn | grep ':8445 '
   ```

   No output means the default port is not currently listening. If 8445 is in
   use, choose an approved free port and prefix the selected start command with
   `NCT_HTTPS_PORT=APPROVED_PORT`.

3. Choose one start script using both the Docker server API and Compose result:

   | What you see | Start script |
   | --- | --- |
   | API 1.41 or newer, and Compose works | `nct-start-compose.sh` |
   | API 1.41 or newer, but Compose fails | `nct-start-docker.sh` |
   | API 1.39 or 1.40 | `nct-start-legacy.sh` |
   | API older than 1.39, or Docker fails | Stop and contact the Range administrator |

4. Manage the Administrator with:

   ```bash
   sh scripts/nct-set-admin.sh
   ```

   To propose a specific username:

   ```bash
   sh scripts/nct-set-admin.sh admin
   ```

   The script shows current Administrator accounts, accepts a username, and
   prompts for the password without placing it on the command line.

## Compatibility scripts

`nct-range-direct-deploy.sh` is an older all-in-one deployment path. It is
retained so previous deployment bundles remain understandable, but it is not
the preferred recurring reset workflow. It requires an explicit Administrator
username:

```bash
sh scripts/nct-range-direct-deploy.sh RANGE_IP APPROVED_ANALYST_CIDR ADMIN_USERNAME [HTTPS_PORT]
```

`nct-set-admin-password.sh` is retained as a narrow password-reset helper. It
also requires an explicit username; it no longer assumes a personal default:

```bash
sh scripts/nct-set-admin-password.sh ADMIN_USERNAME [CONTAINER_NAME]
```

For normal Administrator creation, replacement, rename, or password changes,
prefer `nct-set-admin.sh`.

After a host-folder upgrade fails acceptance, use the exact upgrade receipt
with `nct-rollback-upgrade.sh`. The helper preserves the failed candidate,
restores the verified cold backup, compares the complete restored inventory,
verifies the exact earlier container, image, data-folder mount, and recorded web
port, and starts the earlier container only after the checks pass. Follow the
rollback section in the main quickstart rather than improvising recovery steps.

Before an upgrade changes saved data, `nct-upgrade.sh` stops NCT, uses the
retained original image to complete SQLite's normal stopped-database WAL
checkpoint, and then runs `nct-schema-preflight.py` through the replacement
image with the data mounted read-only. The audit records database integrity, fingerprints, migration
history, originating build identity, known phase2 maintenance tables, and the
database SHA-256. Unknown, incomplete, or altered schema stops the upgrade and
restores the earlier container.

## Candidate Kubernetes storage check

`qualify_kubernetes_storage.py` performs a bounded, disposable check of one mounted
directory before it is considered for a future single-replica Kubernetes deployment.
Run it from a disposable Linux container or pod with the candidate volume mounted at an
otherwise unused path:

```bash
python scripts/qualify_kubernetes_storage.py \
  --root /candidate-data \
  --storage-identity "driver=EXACT_DRIVER;class=EXACT_CLASS;volume=EXACT_VOLUME"
```

The declared identity should describe the exact driver, storage class and volume being
tested without including credentials. The tool creates one private temporary directory,
tests separate-process locks, repeatedly replaces a preexisting file while synchronized
and continuous observer processes check every result and confirm that it never disappears
or becomes partial during replacement, syncs the files and directory,
and checks SQLite WAL behavior including writer contention, checkpoint truncation, reopen,
and integrity. The complete run has a strict time limit. Workers stay bound to the opened
directory rather than looking it up again by path. Successful cleanup removes the private
directory. A timeout or other controller failure marks cleanup unavailable and may name a
remaining private workspace for manual inspection. The tool does not open `analyzer.db`,
inspect retained evidence, or recursively inspect the mounted root.

Exit status `0` and `"overall": "pass"` mean only that the exact mounted environment
passed this bounded check. The report digest detects later alteration when compared with
a separately trusted copy; it is not a signature. A pass does not approve a storage
class or establish Kubernetes, Range, or mission readiness. Save the JSON outside the
candidate data root and retain it with the deployment evidence for later review.

## Kubernetes single-replica renderer

`render_kubernetes_single_replica.py` creates three bounded JSON packages for the
analysis-only profile: the claim, a qualification Job bound to the immutable claim and
volume UIDs, and the one-replica NCT Deployment after a matching passing report is
supplied. It requires an immutable image digest, never calls `kubectl`, never accepts a
Secret value, caps its inputs and output, and refuses mismatched or failed storage
evidence. Follow the complete operator sequence and limitations in
[`docs/KUBERNETES_SINGLE_REPLICA.md`](../docs/KUBERNETES_SINGLE_REPLICA.md).
