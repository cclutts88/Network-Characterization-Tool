# Exact-content compaction operating contract

Exact-content compaction reduces duplicate storage without removing a scan,
collection, download path, evidence observation, filename, attribution, or recorded
timestamp. It applies only when a fresh System Health review proves that a retained
source file and its canonical Artifact Registry file are byte-for-byte identical.
Partially similar files and normalized facts never qualify.

## What changes

For each listed candidate, NCT replaces the duplicate physical file with a hard link
to the verified canonical file. The original path still opens the same complete
bytes, so existing consumers and history continue to work. The paths then name one
physical file and therefore share its filesystem change and modification times.
NCT preserves the logical source and observation timestamps stored in its records.

Compaction requires the source and canonical file to be on the same filesystem. NCT
compares ownership, permissions, and supported security extended attributes before
allowing them to share content. It skips files when those security settings differ,
cannot be compared, or when an unexplained hard link already exists.

## Operating boundary

Compaction exclusion is single-process. Run exactly one NCT application process
against the data directory during dry run, confirmation, compaction, and recovery.
Do not run a second NCT container or worker against that directory, and do not edit,
move, relink, replace, or delete evidence files externally during maintenance.

Automatic pruning remains disabled. Backfill and dry run never remove a physical
copy. Only an administrator can start compaction, and only by confirming the exact
plan produced by a fresh dry run. NCT repeats the path, reference, content, security,
and activity checks before each replacement. Any relevant change invalidates the
reviewed plan.

## Interruption and recovery

Before changing a source path, NCT writes a durable journal entry, creates a recovery
link to the original file, and persists a recovery-required marker. It verifies the
replacement before removing that recovery link. On startup, NCT resolves incomplete
items before scan, collection, scheduler, or analysis workers start. Queued scans
remain queued while recovery blocks evidence changes.

Recovery distrusts saved state: it rechecks path ownership, rejects symbolic links
and paths outside the recognized evidence areas, rechecks the exact content hash,
and restores the original file when a replacement is not intact. If NCT cannot prove
a safe resolution, the recovery-required marker remains and evidence-changing work
stays blocked.

When System Health reports recovery required:

1. Stop every NCT process that uses the data directory.
2. Preserve a copy or snapshot of the entire data directory before investigation.
3. Start one NCT instance so startup recovery can run once.
4. Review System Health. Continue only when the recovery issue is gone and a new dry
   run verifies all references and canonical files.
5. If the block remains, do not delete the marker, recovery directory, journal rows,
   or evidence files. Preserve logs and the data snapshot for repair. A marker must
   be cleared only by successful verified recovery.

## Reading the result

The dry-run estimate is the sum of eligible duplicate file lengths. It excludes
filesystem overhead, compression, journal growth, and database changes. The completed
operation also reports the measured change in filesystem free space. That value can
differ from the estimate and can even be temporarily negative because the database,
journal, and filesystem allocate space differently.

This milestone is development-ready only after its automated crash/recovery tests,
isolated browser demonstration, and independent review pass. It does not by itself
make the build available on `main`, Range-ready, or mission-ready.
