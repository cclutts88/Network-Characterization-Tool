# Multi-analyst foundation

NCT authentication is intentionally disabled in the current single-operator
Test environment. When `NCT_AUTH_MODE=local` is enabled, every page and API
except health and sign-in requires an analyst session.

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
Analyst, or Viewer accounts; passwords are never displayed after creation.

The password file should be mounted read-only, contain only the initial
password, and be removed from the deployment after the first Administrator has
been created. Supplying `NCT_BOOTSTRAP_PASSWORD` directly is retained for
controlled automated tests but exposes the value through container metadata and
must not be used for Range or Mission deployment.

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
disabled, the current browser-local layout behavior remains unchanged.

This is a foundation, not Mission readiness. Account disable/reset, recovery,
external identity integration, comprehensive shared-change auditing, scan
ownership/queuing, and authenticated HTTPS deployment gates remain open.
