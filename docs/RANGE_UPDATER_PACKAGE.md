# Full offline NCT package with Updates and Recovery

Transfer this one ZIP. Extract it into a **new directory**, then open a terminal
inside its `NCT-Air-Gapped-Range-Deployment` folder. Keep the previous package.
The ZIP contains both application and independently pinned recovery-console images,
the optional HTTPS companion image, host setup, recovery tools and internal checksums.
No separate checksum download is required: the setup verifies the included manifest
and image archive. These checks detect damaged content; obtain the ZIP from your
trusted release source. No software is downloaded during installation.

## Before starting

- This is the standalone Docker/Compose package. It does not install a Kubernetes
  updater, change a cluster or enable multiple NCT application replicas.
- The offline Linux host needs working Docker with `--pull=never` support, Python
  **3.9 or newer**, systemd, OpenSSL, curl, ss, flock, tar and standard shell tools.
  These are host prerequisites, not operating-system upgrades supplied by this ZIP.
  Check mode stops before changing NCT if a prerequisite is missing.
  Python may be a separate versioned installation: set `NCT_RECOVERY_PYTHON` to its
  absolute executable path, such as `/usr/bin/python3.9`. Setup validates and pins that
  interpreter for the host service and emergency access. An invalid explicit choice
  does not fall back to another interpreter. System Python is never replaced. Runtime
  paths under home directories are refused because the protected service cannot read
  them. The package does not provide the offline vendor Python installation.
- The retained-data upgrade is qualified from the exact Phase 5 R1 build
  `0.16.0-range-test-20261025-phase5-r1` at
  `be92fb78e938adc3fced581629d4609ac0a43f6a`, with its schema-7 data and a dedicated
  `/var/lib/nct/data` bind folder, or Recovery R1 build
  `0.16.0-range-test-20261027-recovery-r1` at
  `0bd11969ffd81aad7cbc8335af755b80c9af0639` with intact schema-8 data.
  Other versions, named-volume migrations and failed
  installations need their reviewed bridge/recovery procedure. This package never
  turns an unsupported upgrade into an empty installation.
  A version-7 source receives an explicit **version-7 to version-8** migration for the
  corrected Scan History grouping rules. It preserves migrations 1–7 and records
  the new step separately. Unknown or already-drifted schemas are refused. An older
  image must use the preserved version-7 backup for rollback, never the version-8
  database. A version-8 source receives a read-only compatibility check on a
  disposable copy, with no additional schema migration or fingerprint reset.
  Version-6 sources need a separately qualified Phase 5 staging path;
  this package does not perform that bridge.
- Finish scans and device pulls and disable schedules/automatic pulls during the
  maintenance window. Keep the current password: existing accounts are preserved.
- Use the same host IP and HTTPS port as the working NCT. The issuing root CA must
  validate its certificate and that IP must appear in the certificate's SAN.

### Offline Python on older RHEL hosts

If the prerequisite check reports Python 3.6, keep that system interpreter intact.
An administrator can add the vendor's versioned Python 3.9 from matching, trusted
offline RHEL installation media. Use the media's BaseOS and AppStream repositories
with normal vendor signature verification. Preview the transaction first: it must
only add the versioned runtime and required dependencies, with no removals,
downgrades or replacement of system Python. Do not bypass package signatures or
dependency checks. If matching signed dependencies are unavailable, preserve NCT
and obtain the correct offline media before proceeding.

After that runtime is installed, select its actual absolute path for both setup
commands, for example:

```sh
export NCT_RECOVERY_PYTHON=/usr/bin/python3.9
```

The ZIP contains the complete NCT payload, but does not contain vendor operating
system packages. Installing that prerequisite and testing the real recovery service
on the target host remain separate from local package acceptance.

## Check first, then install

Replace `NCT_HOST_IP` with the actual NCT host address. Run as root:

```sh
sh scripts/nct-install-range.sh NCT_HOST_IP check
sh scripts/nct-install-range.sh NCT_HOST_IP
```

Check mode verifies offline prerequisites, every packaged file, the existing data
location, supported source release, ports and existing certificate trust before
changing the application. The install command loads only the verified local images.
For an existing instance it creates a cold backup, independently verifies the saved
data, checks the source's exact schema on a disposable copy and upgrades NCT.
The stopped original container remains available. The replacement preserves the
original environment, mounts, startup command, ports and complete restart policy;
its release identity comes from the new image. Retained originals have automatic
restart disabled. It does not delete evidence, replace accounts or reset passwords.

For a genuinely new installation the same command starts the account setup flow;
it prompts for an administrator password. Do not paste a password into a command.

Default application/recovery ports are **8445 / 8446**. For an existing custom port,
or a different dedicated data root, explicitly set the matching values before both
commands. For example:

```sh
export NCT_HTTPS_PORT=8445
export NCT_RECOVERY_PORT=8446
export NCT_PERSIST_ROOT=/var/lib/nct
```

The recovery listener normally binds the same host IP used in its HTTPS URL. An
administrator using an approved local proxy may explicitly set
`NCT_RECOVERY_BIND_ADDRESS` separately; this does not change the advertised address,
certificate validation or approved-source firewall requirements.

## Finish in the browser

After application acceptance, the trusted host installer enables the independent
recovery service and proves its separate HTTPS endpoint is ready. Collection stays
paused until you sign in to NCT, open **Account and settings → Updates & Recovery**,
select **Open update and recovery workspace** and verify an existing NCT account.
The helper verifies the exact build, saved evidence and readiness, activates normal
background services through a final restart, and returns you to NCT. The console
then stops; the small host launcher remains available for later recovery.

Apply the site's existing approved-source firewall policy to the recovery port
before using it from an analyst workstation. This package does not open a broad
firewall rule. Keep application and recovery ports reachable from the authorized
workstation during updates. Import the issuing CA through the site's normal trust
procedure; do not disable certificate validation.

The default certificate files are under `/var/lib/nct/tls-material`:

- Server certificate/key: `tls/nct-server.crt` and `tls/nct-server.key`.
- **Trust root**: `certs/nct-lab-root.crt`. This is different from the server leaf.
  Set `NCT_CA_FILE` explicitly if your installation uses another issuing CA file.

## If setup stops

Keep the displayed backup, retained container and receipt paths. Do not wipe data
or delete the old image. A failed replacement is stopped and the terminal upgrade
restores its verified pre-upgrade backup before starting the older image; later
candidate data is preserved separately. Unknown schema, unreadable work, missing
image, changed identity or failed verification stops the operation.

If the application upgrade succeeded but recovery-console setup did not finish,
correct the reported host prerequisite/port/certificate issue and run:

```sh
sh scripts/nct-install-range.sh NCT_HOST_IP enable-console
```

This mode requires the exact packaged application already running; it does not
repeat the older-source upgrade. If a recovery service is already installed, preserve
its configuration and receipts and investigate it instead of overwriting it.

When NCT is down, a root operator can reopen the independent console:

```sh
python3 /opt/nct-recovery/nct_update_host.py \
  --config /opt/nct-recovery/config.json --access-code
```

Open the printed HTTPS address and enter the one-use recovery code before it expires.
Application failure does not bypass authentication. The console supports diagnosis,
backup verification, explicit restore, reviewed unfinished-work repair and fixed
start/stop/restart actions. It provides no arbitrary shell.

For existing terminal recovery, use `scripts/nct-diagnostic-report.sh`,
`scripts/nct-recover-installed.sh` and the matching rollback receipt. Read their
printed plan before applying a repair. Preserve valid waiting scans; do not clear
the queue merely to make an update pass.

## Later updates

This ZIP is the one-time **full-package bootstrap**. Later GUI updates use a separately
prepared `nct-update-RELEASE.tar.gz`, containing the image and versioned release
manifest. Do not upload this full ZIP to the GUI. GUI packages never install new
host scripts. The pinned independent console remains available while NCT restarts.
See [Updates and Recovery](docs/NCT_UPDATES_AND_RECOVERY.md) and
[Arkime connector setup](docs/ARKIME_CONNECTOR_RANGE_SETUP.md).

`release.json` identifies exact builds, source files and images. `VALIDATION.json`
records the isolated acceptance and its tested package manifest. Local package
acceptance does not establish acceptance on the actual Range: verify the displayed
build, existing-account sign-in, retained evidence, a stop/start cycle and the
console handoff there before using normal collection again.
