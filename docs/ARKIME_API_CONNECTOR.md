# Automatic Arkime Sessions API intake

This foundation feature lets NCT retain bounded Arkime session evidence without an
analyst exporting each file by hand. It is a read-only evidence connector. It does
not request packet captures, change Arkime, prove that a service is open now, or add
overlapping session counts together.

Range administrators should follow the complete novice-oriented setup and verification
procedure in [`ARKIME_CONNECTOR_RANGE_SETUP.md`](ARKIME_CONNECTOR_RANGE_SETUP.md).
That guide covers Arkime HTTPS, the dedicated API account, secret files, Docker
Compose, the first bounded pull and troubleshooting.

## Deployment configuration

The deployment administrator supplies these settings outside the NCT user interface:

| Setting | Purpose |
| --- | --- |
| `NCT_ARKIME_API_ENABLED=1` | Enables the connector. |
| `NCT_ARKIME_API_URL=https://arkime.example:8005` | Arkime Viewer base URL. HTTPS is required. Credentials, query text and fragments are rejected in this URL. |
| `NCT_ARKIME_API_USERNAME=nct-reader` | Dedicated read-only Arkime account. |
| `NCT_ARKIME_API_PASSWORD_FILE=/run/nct-arkime/password` | Range Compose path for the mounted file containing only that account's password. The password is never saved in a pull definition or evidence record. |
| `NCT_ARKIME_API_CA_FILE=/run/nct-arkime/ca.pem` | Range Compose path for the mounted CA file when the deployment uses its own certificate authority. |
| `NCT_ARKIME_API_TIMEOUT_SECONDS=30` | Whole-request deadline from 3 to 120 seconds. |

NCT uses verified HTTPS, refuses redirects, ignores ambient HTTP proxy settings, asks
for identity encoding and uses HTTP Digest authentication. The connector sends a GET
request only to the configured `/api/sessions` endpoint. Arkime and NCT should use a
trusted certificate chain; disabling certificate verification is unsupported.

For Kubernetes, mount the password and optional CA as read-only Secret volumes and
set the non-secret values on the single NCT application pod. The current SQLite
architecture still requires exactly one application writer; the connector does not
make NCT multi-replica safe.

## What an administrator saves

An administrator creates an immutable pull definition on **Collect / Arkime / Passive
evidence intake**. It records:

- one active Network Scope and its exact saved version;
- an observation-point label;
- an optional Arkime expression;
- Arkime's packet-time bounding mode;
- the first lookback window, cadence, overlap and collection delay; and
- whether automatic collection should begin.

Changing a definition currently means creating a new definition and pausing the old
one. This keeps every queued and completed attempt tied to the settings that governed
it. Creation, enable and pause events retain the responsible operator and time.

## Window and result rules

Before any network contact, NCT saves the exact scope, profile version, connector
identity, connector contract, parser version, query start and end, bounding mode,
expression and request parameters. Queued work whose saved connector or parser version
is no longer supported is rejected before contact. The request asks for at most 1,000
rows, disables facets, selects the supported receipt fields and uses a stable order.
NCT also rejects a response that actually contains more than 1,000 rows, even when it
fits under the separate 10 MiB response limit.

The retained source is the exact decoded HTTP entity returned by Arkime: HTTP transfer
framing is removed by the client, content encoding must be `identity`, and NCT does
not reformat or reserialize the JSON. Accepted responses enter the same whole-file
validation and atomic evidence-publication path as manual Arkime imports.

A result is **Complete** only when Arkime reports a matching-session count equal to
the returned rows. More reported matches makes the retained result **Partial**.
Missing count fields make completeness **Unknown**. Partial and unknown results are
retained for review and stop that automatic definition; neither is discarded or
silently treated as complete. Sensor capture coverage remains Unknown because an API
response cannot prove that the sensor saw every packet.

## Scheduling and recovery

One local worker processes one Arkime pull at a time. A short-lived helper process owns
each HTTPS connection, so NCT can end the entire connection rather than leave a blocked
reader behind. The configured timeout is a hard deadline for DNS, connection,
authentication, response headers and the complete response, including a server that
sends small pieces slowly. Application shutdown terminates the same helper and returns
within its bounded shutdown period.

A successful scheduled window
advances by one cadence, preserving the configured overlap. NCT waits at least one
full cadence before the next scheduled claim, so downtime cannot create an unbounded
catch-up burst. A manual **Pull now** uses a fresh bounded window and does not move the
scheduled cursor.

Pausing prevents new scheduled claims and cancels scheduled work that has not started.
An already-running attempt needs its separate **Cancel** action. Cancellation that
wins before publication produces no evidence. A restart after Arkime contact began
marks the attempt **Interrupted** and does not repeat it automatically. **Retry same
window** creates a new attempt with the original saved start and end times and preserves
whether that attempt belongs to the automatic schedule. A successful manual retry never
moves the scheduled cursor. Once a scheduled window is resolved, an older failed attempt
for that window cannot be retried to move the cursor again.

Saved pull definitions are paged in the interface so every definition remains visible
and controllable as the list grows.

Loading the page or choosing **Refresh pull status** reads NCT's saved records only and
never contacts Arkime. Failed, interrupted, cancelled, partial and unknown attempts
remain visible with their retained window and require an explicit operator decision.

## Current boundary

This is bounded Tier E session intake. The retained sessions are available for source
inspection, but they do not yet create Tier A connection records or feed Current
Network, exact Last Seen, Timeline, Hunt, Reach or Map conclusions. PCAP retrieval and
live Range compatibility validation remain separate gates.
