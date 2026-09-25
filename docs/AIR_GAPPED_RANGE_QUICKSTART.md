# Air-gapped Range quick start

The focused scripts in this package replace the older all-in-one deployment
path. They do not install packages, use the Internet, replace an existing
container named `nct`, or alter the legacy `nmap-terrain-analyzer` deployment.
All operator-created NCT data is stored in the visible host folder
`/var/lib/nct/data`, outside the container and outside the extracted package.

## 1. Extract the package

```sh
cd /root
unzip NCT-Air-Gapped-Range-Deployment-20260924.zip
cd /root/NCT-Air-Gapped-Range-Deployment
```

The scripts use `/root/NCT-Air-Gapped-Range-Deployment` as the full working path.
If the package must live elsewhere, set `NCT_WORKDIR` to that full path before
running a script.

## 2. Check Docker and Compose

```sh
docker version
docker compose version
docker version --format 'Server {{.Server.Version}} / API {{.Server.APIVersion}}'
```

- **Current / standard path:** Docker server API **1.41 or newer**. If
  `docker compose version` succeeds, use `nct-start-compose.sh`; if it fails,
  use `nct-start-docker.sh`.
- **Older recurring Range path:** Docker server API **1.39 or 1.40**. Use
  `nct-start-legacy.sh`. The repeatedly reset Range VM previously observed as
  Docker 18.09 / API 1.39 is in this category.
- **Unsupported by these scripts:** Docker server API older than **1.39**.
  Stop and use the separately validated NCT appliance path rather than trying
  to weaken the host configuration.

The API value is the decision point; the displayed Docker product version is
included for the deployment record. The `legacy` path relaxes the security
profile only for the NCT container and should not be used on API 1.41 or newer.

The old standalone `docker-compose` command is not required by these scripts.

## 3. Migrate an existing `nct-data` volume, when present

Skip this section on a new installation. If an earlier NCT deployment used the
Docker volume named `nct-data`, verify it exists and run the migration:

```sh
docker volume inspect nct-data
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-migrate-data.sh
```

The migration refuses to run during active NCT work, stops and retains the old
container under a timestamped rollback name, copies the volume into
`/var/lib/nct/data`, and compares every copied file before reporting success.
It does not delete or modify `nct-data`. Keep the printed migration receipt and
rollback-container name until the new deployment has been accepted.

## 4. Check port 8445

```sh
ss -ltn | grep ':8445 ' || echo PORT_8445_FREE
sudo ss -lntp | grep ':8445 '
```

If the first command prints `PORT_8445_FREE`, use the default. If a listener is
shown, open the selected start script and change the clearly marked line near
the top:

```sh
HOST_PORT=8445
```

Replace `8445` with an approved unused TCP port, save the file, and repeat the
port check with the new number.

## 5. Choose one path: new installation or upgrade

Use **5A** for a new installation or for the first start after the volume
migration in step 3. Use **5B** when the existing `nct` container already stores
its `/data` files in `/var/lib/nct/data`. Do not run both paths.

### 5A. Start a new or newly migrated installation

Substitute the Range address. The script will ask for the Administrator username
to create, then prompt twice for its password. The username does not need to be
`admin`. Spaces and symbols are accepted in the password, the password is not
placed on the command line, and the temporary bootstrap secret is removed after
the chosen password is set.

Older Range Docker:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-start-legacy.sh RANGE_IP
```

Current Docker without Compose:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-start-docker.sh RANGE_IP
```

Current Docker with the Compose plugin:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-start-compose.sh RANGE_IP
```

On a migrated installation, the start script preserves all existing accounts
and does not prompt for or reset a password. On a new installation, it creates
the selected Administrator and securely prompts for the initial password.

### 5B. Upgrade an existing host-folder installation

If `docker inspect nct` shows that `/data` already points to
`/var/lib/nct/data`, use the upgrade helper instead of removing the current
container by hand:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-upgrade.sh RANGE_IP
```

The helper refuses active scans or collections, verifies and loads the packaged
image, stops NCT, creates a checksum-protected data backup, retains the prior
container under a timestamped rollback name, starts the release, and confirms
that stored file and record counts did not decrease. It automatically uses
Compose when available. To force the older compatibility path, append
`legacy`; to force current Docker without Compose, append `docker`.

When the helper finishes, keep the printed backup, receipt, and rollback
container names until the release has been accepted. Continue with step 6.

## 6. Restrict Range access

Substitute the same address, selected HTTPS port, and approved analyst network:

```sh
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=APPROVED_ANALYST_CIDR destination address=RANGE_IP port port=8445 protocol=tcp accept'
firewall-cmd --reload
```

If `HOST_PORT` was changed, use that port in the firewall rule.

## 7. Open NCT

Open `https://RANGE_IP:8445`, or the replacement port selected above. The
Range uses a self-signed HTTPS certificate, so the browser warning is expected.
Use the browser's approved option to continue to the site.

Sign in with the Administrator username selected in step 5A. On an upgrade,
sign in with an existing Administrator username. Do not assume the username is
`admin`.

## 8. Change or recover the Administrator later

Run the account helper with no hard-coded username:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-set-admin.sh
```

It lists the current Administrator accounts and lets the operator keep the
current username, create a replacement Administrator, and set a new password.
When replacing the only active Administrator, it creates the new account before
offering to disable the old one. Existing operator data is not moved or deleted.

For emergency password recovery with a verified backup first, use:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-admin-recover.sh --admin-user ADMIN_USERNAME
```

The recovery helper recognizes both the new `/var/lib/nct/data` host folder and
older named volumes. It stops NCT only after approval, writes a backup under
`/var/lib/nct/deployment/backups`, resets the selected Administrator, revokes
that account's earlier sessions, and returns the container to its prior state.

## 9. Verify the deployment

```sh
docker ps --filter name=nct
docker logs nct
docker inspect nct --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
find /var/lib/nct/data -maxdepth 2 -type f | sort
curl -k https://RANGE_IP:8445/health
```

Confirm that the health response shows version `0.15.3` and build ID
`0.15.3-range-20260924`. Sign in, open **Nmap Scans**, and confirm that the
existing scan history is present. Then open **Network Devices**, expand an
existing collection, and download `manifest.json` and `stdout.txt`. Confirm
that both files save through the browser before accepting the upgrade.

For the Cisco acceptance check, collect the known test router with the same
read-only Cisco preset used previously. Confirm that the result is completed,
the displayed output is not blank, and its saved configuration file downloads.
If the device rejects a command, NCT should retain the returned Cisco message
in the evidence instead of reporting an empty successful collection.

The `/data` mount shown by `docker inspect` must point to
`/var/lib/nct/data`. Keep that folder on the VM's local disk and include
`/var/lib/nct` in the normal Range or Proxmox backup scope. Do not place the
live folder on NFS, SMB, OneDrive, or another synchronized/network filesystem.

## 10. Roll back after a failed acceptance check

Only use this if the new host-folder deployment fails acceptance. Substitute
the exact rollback-container name printed by `nct-migrate-data.sh`:

```sh
docker stop nct
docker rm nct
docker rename nct-volume-rollback-TIMESTAMP nct
docker start nct
```

For a volume migration, this returns to the original container and retained
`nct-data` volume. It does not remove `/var/lib/nct/data`, so the verified copy
remains available for investigation or another migration attempt.

For an upgrade, substitute the exact rollback-container name printed by
`nct-upgrade.sh` and use the same stop, remove, rename, and start sequence. The
checksum-protected pre-upgrade backup remains under
`/var/lib/nct/deployment/backups`.

## 11. Add offline SearchSploit data, when needed

For offline SearchSploit data, upload the unextracted official Exploit-DB
archive through **Hunt -> SearchSploit enrichment -> Manage offline database**.
