# Evidence Library

Open **Evidence Library** from the hamburger menu. Nmap runs, individual imported
XML encounters, and device uploads/collections appear together. Use recorded
network name/CIDR, device address, filename or source ID text, type, exact Network
Scope, analyst and inclusive UTC saved-date filters. All chosen filters must match.
Search is literal text, not CIDR containment. Imported XML without recorded network
metadata can still be found by filename and source identity.

The catalog is read-only. It never contacts a device, queues processing, repairs,
compacts or parses original evidence content. **Files and context** opens one
encounter and reuses existing protected source downloads. **Open analysis** opens
the exact retained Nmap run or device collection; unavailable analysis remains
unavailable until its separate normal workflow is deliberately used.

Imported identical bytes retain separate encounter IDs, analysts, times and exact
scope assignments. The shared-byte download may use the first stored filename.
No encounter-specific analysis link is offered until that analyzer can preserve
the exact observation context. Inspect imports through Import & Investigate.

## Device metadata cache

The existing current-device selector intentionally excludes old/unprocessed data.
The library instead uses a disposable SQLite metadata index under the protected
per-user temporary runtime directory `nct-library-<uid>`. The filename hashes the
database path; the index records the database instance and exact device root.
It is outside the retained evidence mount, so existing recovery inventories and
backups are unchanged. Losing this cache loses no evidence.

Startup rebuilds the device metadata baseline, reading at most 2 MiB from each
allowed run's manifest. Oversized, missing, malformed and unsafe metadata have
explicit unavailable rows. No source output, configurations, commands, credentials
or full manifests are copied into the index. Only bounded display fields and a
manifest digest are stored. Normal central manifest publication marks the index
dirty **before** source replacement and updates it afterward. A failed rebuild
cannot be promoted to complete by one later publication. A cache error never
fails collection; library device coverage becomes explicitly incomplete instead.

Library GET requests use read-only SQLite connections, a consistent read
transaction, filters before keyset pagination and bounded visible-row metadata
checks. Current deletion/preparing authority overrides cache state. Visible drift
or changed authority/context suppresses source actions. The normal protected
source endpoint checks again when opened; catalog status is never an integrity
certificate. Scopes come from retained scan context, explicit per-observation
import assignment or current-revision device assignment, never preferences.

Direct administrator filesystem changes outside supported publication paths
require a restart to refresh the catalog, including changes that would affect
filtered-out rows. Device coverage text states this boundary. The library does
not perform a hidden filesystem walk on each request to detect outside edits.
The source table and original files remain authoritative. An incomplete cache
does not mean there is no device evidence.

The separate administrator Configuration & Source viewer remains planned work.
