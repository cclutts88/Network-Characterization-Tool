# Multi-analyst foundation

NCT authentication remains optional for a single-operator Test deployment and
is required by the Range deployment profile. When `NCT_AUTH_MODE=local` is
enabled, every page and API except health and sign-in requires an analyst
session.

The first authenticated start requires an Administrator and a password file:

```text
NCT_AUTH_MODE=local
NCT_BOOTSTRAP_ADMIN=nctadmin
NCT_BOOTSTRAP_PASSWORD_FILE=/run/secrets/nct_bootstrap_password
NCT_SESSION_HOURS=12
NCT_COOKIE_SECURE=1
```

After sign-in, every primary page shows the active analyst and role. An
Administrator can open **Accounts** from that control to create named Admin,
Analyst, or Viewer accounts; enable or disable accounts; reset passwords; and
review account audit history. Passwords are never displayed after creation or
reset. Disabling an account or resetting its password revokes all its sessions.

The password file should be mounted read-only, contain only the initial
password, and be removed from the deployment after the first Administrator has
been created. Supplying `NCT_BOOTSTRAP_PASSWORD` directly is retained for
controlled automated tests but exposes the value through container metadata and
must not be used for Range or Mission deployment.

The rapid deployment launcher performs this sequence automatically when it
finds an empty account store. It requires an operator-selected Administrator
name and an interactive, supplied-file, or generated password; there are no
default credentials. It verifies the new account, removes the secret mount, and
restarts NCT without bootstrap configuration before reporting success. Upgrades
that find existing accounts do not bootstrap again.

Passwords use per-user random salts and PBKDF2-SHA256. Session tokens are random,
stored only as hashes, sent in HttpOnly SameSite cookies, and expire. Viewer
accounts can read shared evidence but cannot perform mutations. Analysts can
work and save personal layouts. Administrator actions are required to create
accounts or publish and unpublish a Map layout.

When authentication is enabled, audit ownership for scans, generated packages,
profiles, schedules, safety exclusions, Saved Networks, OS reviews, and device
collection plans is taken from the signed-in server session. A client-supplied
operator label cannot impersonate a different analyst.

Named Map layouts become server-persistent and owner-scoped in authenticated
mode. Updates include a version so a stale browser cannot silently overwrite a
newer layout. Shared layouts remain owned by their creator; another analyst can
load one without modifying or deleting the owner's copy. With authentication
disabled, the current browser-local layout behavior remains unchanged. Each
analyst can mark exactly one visible personal or shared layout as the default;
that preference affects only their account and opens automatically on Map.

Every primary page also provides two collapsed investigation-note rails.
**Personal notes** open from the left and follow the signed-in analyst throughout
NCT. They support nested folders, movable notes, page/record context links, and
optimistic version checks. **Shared notes** open from the right and show only
material explicitly published to the current Device, Nmap, Analyze, Hunt, or
Map page. Shared material is read-only to other analysts and identifies its
owner. Sharing or unsharing a folder applies to its complete branch. A selected
note or folder tree can be downloaded as a portable Markdown document.

An authorized host operator can use `scripts/nct-admin-recover.sh` when all
Administrators are locked out. Recovery is limited to an existing Administrator,
requires no active work, creates a backup, resets through a password-file mount,
and revokes the account's existing sessions. It cannot create or promote users.

This is a foundation, not Mission readiness. External identity integration,
comprehensive shared-change auditing, scan ownership/queuing, the formal
promotion gate, and fully validated authenticated HTTPS deployment remain open.
