# NCT Range Operator Scripts

This directory contains both the current small operator scripts and older
deployment automation retained for compatibility.

## Recommended reset workflow

1. Confirm Docker is available:

   ```bash
   docker --version
   docker compose version
   ```

2. Confirm the default NCT HTTPS port is free:

   ```bash
   ss -ltn | grep ':8445 '
   ```

   No output means the default port is not currently listening. If 8445 is in
   use, edit `HOST_PORT=8445` near the top of the selected start script and
   choose an approved free port.

3. Choose one start script:

   - `nct-start-compose.sh` when `docker compose version` succeeds.
   - `nct-start-docker.sh` when the modern Docker CLI is present but Compose is not.
   - `nct-start-legacy.sh` only for the older Range Docker engine compatibility path.

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
