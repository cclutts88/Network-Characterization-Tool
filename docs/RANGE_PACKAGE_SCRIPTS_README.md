# NCT Range Operator Scripts

This directory contains both the current small operator scripts and older
deployment automation retained for compatibility.

## Recommended reset workflow

The authoritative instructions are in
`../AIR-GAPPED-RANGE-QUICKSTART.md`. Follow that guide from the beginning. This
file is a short reference for the scripts and must not replace the required
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
image with the data mounted read-only. The audit records database integrity,
fingerprints, migration history, originating build identity, known version-4
maintenance tables, and the database SHA-256. Only exact reviewed version-4 and
version-5 Range sources are accepted. Unknown, incomplete, or altered schema stops
the upgrade and restores the earlier container.

If the retained earlier container itself cannot restart, use
`nct-recover-unhealthy-upgrade.sh` only through step 6A of the main guide. It
performs the same read-only schema gate without requiring the old application
to run, independently verifies a cold backup, retains both failure sources, and
does not restart an incompatible old image after replacement-written data.

## Evidence-preserving unfinished-scan recovery

Use the Active Scans **Scan queue self-check** first. It reads saved scan,
schedule and ownership records without changing them. If it reports unfinished
work, run this preview from the extracted package:

```bash
sh scripts/nct-reset-unfinished.sh --container nct
```

The host helper refuses a shared data mount, stops the exact container, records
its non-secret runtime identity, creates a complete cold backup outside retained
data, independently extracts and verifies every file, and recalculates the exact
recovery plan. Preview mode restores the previous running state and changes no
scan record. After an administrator reviews the printed plan, apply it with:

```bash
sh scripts/nct-reset-unfinished.sh --container nct --apply
```

Apply requires the displayed plan confirmation. Completed scans and evidence
remain unchanged. Unstarted waiting scans retain their order. Work that may have
contacted the network becomes Interrupted, affected schedules stay paused for
review, and NCT restarts with automatic contact paused. Review the affected rows
in Active Scans, then use **Resume preserved scans** to allow preserved waiting
Nmap work to pass through the normal scope, No-Strike and pre-contact checks.
Use **Resume passive pulls** separately to authorize automatic Arkime connector
contact. Neither review action authorizes the other.

Keep the backup, plan and receipts. The helper stops instead of guessing when it
finds an unfamiliar schema or state, an unfinished migration, unresolved
compaction, database damage, another container sharing the data, a failed backup
verification, or a plan that changed after review. NCT restarts only after Docker
successfully proves the temporary recovery helper is absent. If that inventory
cannot complete, NCT remains stopped with automatic restart disabled and reports
the manual review boundary.
