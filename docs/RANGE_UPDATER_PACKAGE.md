# Full offline NCT package with Updates and Recovery

Transfer this one ZIP when the Range transfer service accepts it. If it rejects the
ZIP for size, transfer every numbered piece and use the included join instructions
to reconstruct and verify the identical complete ZIP before extracting it. This
works for both fresh and retained-data routes. Never upload a split piece or the full
ZIP into the GUI updater; that page accepts only the included `nct-update-….tar.gz`.
Extract the complete ZIP into a **new directory**, then open a terminal inside its
`NCT-Air-Gapped-Range-Deployment` folder. Keep the previous package.
The ZIP contains both application and independently pinned recovery-console images,
the optional HTTPS companion image, host setup, recovery tools and internal checksums.
No separate checksum download is required: the setup verifies the included manifest
and image archive. These checks detect damaged content; obtain the ZIP from your
trusted release source. No software is downloaded during installation.

## Before starting

### Choose the installation path

- If the application is the exact Fresh-r2 build and Updates & Recovery is already
  the exact Fresh-r3 helper/console stack named in `release.json` under
  `helper_upgrade_source`, use the separate helper/console upgrade below. Do not
  rerun the first-time installer over its saved state.
- If there is no independent helper installed, use the first-time instructions
  below for the explicitly supported sources. The installer adds and verifies the
  independent recovery path while preserving the running application, account and
  evidence. It does not replace the application in the terminal. Afterward, open
  Updates & Recovery and apply the included `nct-update-….tar.gz` there. Other
  builds need a reviewed bridge.

### Existing Fresh-r2 application with Fresh-r3 helper and console

This path is limited to the accepted Fresh-r2 application and the exact installed
Fresh-r3 host helper and independently pinned Fresh-r3 console, all named in
`helper_upgrade_source`. It refuses other builds or helper versions, including an
untouched Fresh-r2 helper stack, as well as unfinished update/recovery operations,
changed mounts or weakened console settings.
Keep the current application, evidence, accounts and recovery receipts in place.

An administrator runs these steps on the Linux NCT host from the newly extracted
package folder. These are host steps, not a browser upload. Read the protected
interpreter from the installed service before previewing:

```sh
systemctl cat nct-recovery-host.service | grep '^ExecStart='
```

The first path after `ExecStart=` is the pinned Python 3.9-or-newer executable.
Use that full path in both commands below. Stop if the service is missing, more than
one `ExecStart` is shown, or that executable does not report Python 3.9 or newer.

1. Check the package: `sha256sum -c PACKAGE-MANIFEST.sha256`. Stop if any file fails.
2. Load its local images: `docker load -i offline-images/nct-range-images.tar`.
   This imports images without stopping or replacing NCT.
3. Read `console_image` in `release.json`. Use that exact tag in place of
   `CONSOLE_IMAGE` below; do not use an older console or a floating `latest` tag.
4. Preview: `/full/path/from/ExecStart scripts/nct-upgrade-recovery.py --console-image CONSOLE_IMAGE`.
   Success says: **Checks passed. NCT is unchanged. Use --apply during the
   maintenance window.** It leaves the application, helper and console unchanged.
   Any other result means stop; do not add `--apply`.
5. During the maintenance window, repeat with `--apply`. Progress is printed for
   each saved stage. The helper and console stop briefly; the NCT application is
   not replaced by this operation. The new console is checked over verified HTTPS
   and returned to its normal stopped state.
6. Open NCT → **Account and settings → Updates & Recovery → Open update and recovery
   workspace**. Transfer the included `nct-update-….tar.gz` to the computer running
   that browser and follow Upload → Review → Apply → Verify.
   That separate application update uses the existing-account and backup checks.

If the helper upgrade is interrupted, **do not reinstall or delete its state**.
Keep the new full package and the private `helper-upgrade.json` beside the installed
helper config. An administrator can repeat the same command with `--rollback` to
restore the proven original helper/console. Changed or ambiguous identities stop
recovery for review. The retained originals and private journal are not evidence
compaction candidates. A completed journal is not replayed as a new transaction.

Local qualification uses a controlled service process in place of systemd; actual
host service and browser trust acceptance remain separate Range checks.

- This is the standalone Docker/Compose package. It does not install a Kubernetes
  updater, change a cluster or enable multiple NCT application replicas.
- The offline Linux host needs working Docker with its local Engine interface, Python
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
- The ordinary full-package installer assumes the independent recovery helper is not
  already installed. The exact mixed controller state named at the start of this
  guide instead uses the reviewed helper/console upgrade, followed by the included
  GUI application update. Preserve its configuration and receipts; the ordinary
  installer correctly refuses that case before loading images or changing the
  application. An untouched Fresh-r2 helper/console stack is not an accepted source.
- Finish scans and device pulls and disable schedules/automatic pulls during the
  maintenance window. Keep the current password: existing accounts are preserved.
- This full package qualifies the Fresh-r2 application
  `0.16.0-range-test-20261102-fresh-r2` at commit
  `ba2124aad40dc9f4f718c2799db35d9703a5f89d` only when it is paired with the exact
  Fresh-r3 helper and console declared in `release.json` under
  `helper_upgrade_source`. Use the full ZIP to update those recovery components
  first, then upload its included application update in the browser so the complete
  installed stack reaches this release.
  The operator keeps the existing account and retained evidence; no new password is
  selected during an update.
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

## Add recovery first, then update the application in the browser

Replace `NCT_HOST_IP` with the actual NCT host address. Enter the root shell first,
then set any environment values below and run both commands in that same shell:

```sh
sh scripts/nct-install-range.sh NCT_HOST_IP check
sh scripts/nct-install-range.sh NCT_HOST_IP
```

Check mode verifies offline prerequisites, every packaged file, the existing data
location, supported source release, ports and existing certificate trust before
changing the application. The install command loads only the verified local images,
briefly performs the checked restart needed to attach the recovery handoff, and
installs the independent recovery helper and console. The same source application,
account, evidence, data path, environment, mounts, startup command, ports and restart
policy remain in place. It does not apply the new application image, delete evidence,
replace accounts or reset passwords.

When the terminal reports completion, open NCT → **Account and settings → Updates &
Recovery → Open update and recovery workspace**. First complete **Verify sign-in and
finish** with the existing account. Wait for recovery setup to report completion and
confirm NCT still shows the supported source build. Then return to NCT, reopen the
workspace, upload the included `nct-update-….tar.gz`, review the identified source and
saved-work checks, apply it, and verify the existing account again for that separate
application update. The recovery workspace performs the cold backup,
schema check, application replacement, retained-evidence verification and protected
restore if needed. The terminal updater deliberately refuses this retirement-capable
release before stopping the source application; it is not a fallback update route.

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

Before installing, an administrator must allow the application and recovery ports
from the authorized workstation and prepare trust in the issuing CA. The installer
does not change firewall policy or disable certificate validation.

After recovery setup, open **Account and settings → Updates & Recovery**, select
**Open update and recovery workspace**, and first verify the existing account to
finish recovery setup. Wait for completion, return to NCT, reopen the workspace, then
upload the included update, review it, apply it, and verify the existing account again
for the application update. The helper verifies the exact source, saved
evidence, backup and new readiness, activates normal background services through a
final restart, and returns you to NCT. The console then stops; the small host launcher
remains available for later recovery.
The application address is `https://NCT_HOST_IP:8445` unless a custom port was
selected. Enter the existing account under **3. Verify sign-in and finish**, then
select **Verify sign-in**. Finish by confirming that recovery reports completion, NCT displays the new
build, the existing account works, and representative saved evidence is visible.

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

When NCT is down, a root operator can reopen the independent console. Save and use
the exact emergency command printed during installation: it contains the selected
Python interpreter and actual installation paths. For example, where a separate
Python 3.9 was selected and the default paths were used:

```sh
/usr/bin/python3.9 /opt/nct-recovery/nct_update_host.py \
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

Do not upload this full ZIP to the GUI. For the exact Fresh-r2 path above, the ZIP first
upgrades the protected host helper and pinned console, then its included
`nct-update-RELEASE.tar.gz` updates the application. After that full transition, later
application-only updates may use a separately prepared GUI package when its manifest
names the exact installed source. GUI packages never install host scripts or a console.
The pinned independent console remains available while NCT restarts.
See [Updates and Recovery](docs/NCT_UPDATES_AND_RECOVERY.md) and
[Arkime connector setup](docs/ARKIME_CONNECTOR_RANGE_SETUP.md).

`release.json` identifies exact builds, source files and images. `VALIDATION.json`
records the isolated acceptance and its tested package manifest. Local package
acceptance does not establish acceptance on the actual Range: verify the displayed
build, existing-account sign-in, retained evidence, a stop/start cycle and the
console handoff there before using normal collection again.
