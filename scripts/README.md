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
