# Range observability validation record

This is the technical evidence record for the isolated Arkime and Security Onion
integration range. The roadmap intentionally carries only milestone status. This
record preserves the exact checks, rollback points, retained evidence and known risks.

## 2026-10-20 — inventory and separation boundary

- Proxmox node: `Rachael`.
- Lab routing and endpoints: pfSense VM 254, VyOS VM 105, VLAN 10 endpoint VM 106
  and VLAN 20 endpoint VM 108.
- Passive systems: Arkime VM 118, Security Onion manager/search VM 110, home sensor
  VM 112 and range sensor VM 117.
- At the end of the recorded Arkime tests, VM 110, VM 112 and VM 117 remained stopped.
- Arkime management used Blue Net address `172.22.70.30/24`. Its capture interface
  was unnumbered and had no management route.
- None of these tests connected the Proxmox lab to the deployed Work Range NCT.

## Rollback points

- VM 118 snapshot: `pre-arkime-capture-fix-20261019`.
- Arkime capture configuration backup:
  `/opt/arkime/etc/config.ini.pre-capture-fix-20261019`.
- Identity correction backup:
  `/opt/arkime/etc/config.ini.pre-identity-resolution-20261020`.
- VLAN validation host backup:
  `/root/nct-vm118-config.pre-vlan-validation-20261020`.
- VLAN validation guest backup:
  `/opt/arkime/etc/config.ini.pre-vlan-validation-20261020`.
- VLAN mirror transition log:
  `/root/nct-vlan-validation-transition.log`.

The Proxmox thin pool warned that total provisioned capacity exceeded physical
capacity when the snapshot was created. The snapshot completed, but the warning
remains an unresolved lab-capacity risk.

## Bounded pfSense-LAN validation

A temporary, reboot-volatile two-direction traffic-control mirror copied the pfSense
LAN bridge-facing port `fwpr254p1` to Arkime capture tap `tap118i1`. The rollback
was to remove only the validation-owned mirror and its `clsact` qdisc.

A five-echo ICMP test and an HTTPS HEAD request from the Proxmox host to pfSense LAN
address `192.168.1.1` completed with no ping loss. Arkime capture-interface counters
increased. This proved that bounded mirror path; it did not prove complete coverage.

Duplicate `dropUser=nobody` and `dropGroup=daemon` settings were corrected to the
dedicated `arkime:arkime` identity. A stale
`/tmp/arkimemanagement.stoppedsessions` file owned by the previous identity blocked
stopped-session persistence. Changing that one runtime file to `arkime:arkime`
removed the repeated save error without deleting evidence.

Arkime's configured 256 KiB direct-write buffer explained why the first small probes
created indexed metadata before a nonzero packet file appeared. A bounded 1,000-packet,
1,400-byte ICMP run retained 57,344 compressed packet bytes. After restarting capture,
a second bounded 300-packet run retained a new 16,384-byte packet file. OpenSearch,
capture and viewer were active after restart, the session index increased to three
documents, and no new stopped-session ownership errors appeared during that window.

### Retained structured-session export

VM 118 retains these files under
`/srv/arkime-data/exports/nct-validation-20261020/`:

- `query.json`
- `export.json` — 10,528 bytes
- `metadata.txt`

The metadata records UTC, sensor `arkimemanagement`, validation scope
`Proxmox-Arkime-Lab-Servers` (`192.168.1.0/24`), source `192.168.1.2`, destination
`192.168.1.1`, time window `1792515600000..1792516530654`, and four returned
sessions. The exact `export.json` SHA-256 is
`880f339c17211ad2457ede9a1f52a2e121b704315f713af09710c48b350a917d`.

This proves the retained structured-session export path used for Tier D validation.
It does not satisfy the separate Tier A summary-export requirement.

## Bounded VLAN 10 and VLAN 20 validation

Before the test, the pfSense mirror was temporarily removed. A temporary, unnumbered
VM 118 capture adapter was attached to the VyOS VLAN-aware lab bridge, Arkime capture
was moved to that adapter, and validation-owned two-direction mirror rules copied the
VyOS trunk port `fwpr105p1` to `tap118i2`.

- VLAN 10: 17 ICMP echoes to `172.22.10.10`; all 17 returned.
- VLAN 20: 23 ICMP echoes to `172.22.20.10`; all 23 returned.
- Bounded capture: 188 packets captured, 189 received by the filter, zero dropped by
  the kernel.
- Packet text showed 802.1Q VLAN 10 and VLAN 20 tags and request/reply pairs.
- The capture also observed background DNS and NTP traffic from both endpoints.
- Arkime query for both endpoint addresses returned 38 sessions.
- Arkime query `vlan == 10` returned 21 sessions.
- Arkime query `vlan == 20` returned 17 sessions.

Retained text evidence:
`/srv/arkime-data/exports/nct-validation-20261020/vlan-validation.txt`

SHA-256:
`4496b5d27650713ebac44ede3eb43a29a040d2a3823986a00fc5c64fe297c13b`

These are Arkime session counts. They are not unique-connection counts and do not
prove duplicate reconciliation or continuous coverage.

## Restoration check

After the VLAN test:

- the validation-owned VyOS mirror rules were removed;
- the `fwpr105p1` `clsact` qdisc was deleted because the recorded pre-state had none;
- Arkime capture was restored to `enp6s19` and was active;
- the temporary VM 118 adapter was removed;
- the original pfSense-LAN mirror on `fwpr254p1` to `tap118i1` was restored; and
- four pings to `192.168.1.1` returned without loss and HTTPS returned status 200.

## Known stability limitation

Before the controlled restart window, OpenSearch had exited after about four hours
with `SIGSEGV`. Arkime capture then lost database access. Disk space, the dedicated
packet volume, memory and swap were not exhausted at the observed failure. The guest
kernel also reported unstable TSC timing after clock skew. That timing signal is a
possible contributor only; it is not a proven cause of the crash.

A short successful restart does not close this limitation. Extended soak, resource,
restart and reconciliation checks remain required before any readiness claim.

## Open acceptance work

- Security Onion manager/search and both intended sensors.
- UniFi syslog receipt and source attribution.
- Persistent mirror ownership and restart behavior.
- Duplicate visibility across observation points.
- Retention measurements under sustained traffic.
- Implemented and verified NCT passive-evidence ingestion.

## 2026-10-20 — Security Onion startup blocker

The first attempt to start manager/search VM 110 stopped before guest boot. Proxmox
reported:

`Activation of logical volume chrisJr/chrisJr is prohibited while logical volume chrisJr/chrisJr_tmeta is active.`

The Proxmox storage status API reported the `chrisJr` LVM-thin storage as enabled but
inactive, with zero available, total and used values. The LVM-thin inventory reported
thin pool `chrisJr/chrisJr` with inactive state. Those zero capacity figures do not
establish that the pool is empty or exhausted, and the observation does not by itself
prove corruption. The manager and both sensors use disks on that storage, so sensor
startup was not attempted.

No storage repair, disk move, VM configuration change or retry was performed. The
manager, range sensor and home sensor remain stopped. Before any repair, record the
complete volume-group, thin-pool, device-mapper and Proxmox storage state and account
for running VMs that may already have active volumes from the same pool. This record
does not authorize or prescribe a repair.

## 2026-10-20 — authorized clean-rebuild boundary

The existing Security Onion installation was not complete and has no Security Onion
evidence that needs preservation. The operator authorized removal and recreation of
only these unfinished VMs, reusing their names:

- VM 110 — `SO-ManagerSearch`
- VM 112 — `SO-Sensor-Home`
- VM 117 — `SO-Sensor-Range-BlueNet`

This authorization does not include deleting or reformatting the shared `chrisJr`
pool, deleting any other VM, or performing broad orphan-volume cleanup. The inactive
pool also contains records associated with other VMs. If normal removal cannot reach
the old Security Onion disks, their exact old volume identities must be recorded and
left untouched until a separately reviewed storage action is available.

Recreation is gated on demonstrated healthy local capacity for 2,200 GiB of requested
virtual disks plus operational headroom. Inaccessible old disks do not count as
reclaimed space. VM identities, stopped state, snapshots, attached disks, network
adapters, HA membership and replication membership must be recorded before removal.

The intended rebuilt layout is:

| VM | Role | Management | Passive capture | Provisional allocation |
|---|---|---|---|---|
| 110 | Manager/Search | `172.22.70.10/24` on `vmbr5` | None | 8 vCPU, 24 GiB RAM, 400 GiB disk |
| 117 | Range sensor | `172.22.70.20/24` on `vmbr5` | `vmbr3`, `vmbr4` | 8 vCPU, 16 GiB RAM, 900 GiB disk |
| 112 | Home sensor | `172.22.70.21/24` on `vmbr5` | `vmbr2` | 8 vCPU, 16 GiB RAM, 900 GiB disk |

The management gateway is `172.22.70.1`, DNS is `10.0.0.53`, and the intended console
address is `https://172.22.70.10`. Address-conflict checks remain required before use.
The operator supplied one temporary administrator credential for all three nodes. Its
value is intentionally absent from source control and documentation and must be
rotated after acceptance.

The supported Security Onion roles are ManagerSearch and Sensor. Arkime remains on
separate VM 118 rather than being added to the Security Onion sensor guests. This is a
documented clarification of the earlier conversational phrase "Arkime on the
sensors" and avoids duplicate packet-platform resource use inside each sensor.

The clean rebuild is not started and does not close Security Onion acceptance. It is
complete only after manager health, both sensor joins, capture-interface isolation,
known-event search, restart behavior, retention measurement and source attribution
all pass.

## 2026-10-20 — replacement-storage deviation cleared

The preflight review stopped the planned activation of the shared `chrisJr` pool.
One physical member reported 113 reallocated sectors, a raw pending-sector value of
65,535 and nine offline-uncorrectable sectors. The kernel had not logged a current
I/O error and the drive still reported an overall SMART pass, but those attributes do
not satisfy the clean-disk condition for a shared-pool activation attempt. No pool
activation, repair, metadata change, force option or old-volume cleanup was attempted.
All `chrisJr` volumes, including VM 116 and the old Security Onion disks and snapshots,
remain unchanged.

The separate `Das_Boot` destination was verified as a locally attached 12 TB Seagate
IronWolf disk with XFS mounted read/write, approximately 11 TB available, no
reallocated, pending, offline-uncorrectable or reported-uncorrectable sectors, and no
disk or XFS error in the current kernel log. It is already configured by Proxmox to
store VM images. The drive is one shared rotating disk, so it is a test-range recovery
destination with a performance and resilience limit. It is not evidence of production
storage readiness, and retention acceptance must be measured after the sensors run.

Before replacement provisioning, the complete VM 110, 112 and 117 configuration and
snapshot records plus the exact old `chrisJr` volume identities were copied outside the
affected pool to a root-only directory under `Das_Boot` and protected by a SHA-256
manifest. The values of previously recorded temporary credentials remain excluded from
this document and source control.

The cleared replacement procedure preserves the stopped old VMs under display names
beginning `RETAINED-STORAGE-BLOCKED-` and leaves every old disk, snapshot and network
reference attached to those records. Fresh manager/search and sensor guests use unused
VM identifiers, new disks created only on `Das_Boot`, and the intended original role
names. This avoids disk-removal commands whose storage-deletion behavior could affect
the unhealthy pool. The existing and replacement guests must never run together or
claim the same management address. The independent quality gate returned
**CLEAR — DOCUMENTED DEVIATION** for this bounded procedure.

This deviation authorizes replacement provisioning only. Security Onion acceptance
still requires manager health, both sensor joins, unnumbered capture interfaces,
known-event search, restart behavior, retention measurement and source attribution.

## 2026-10-20 — replacement guests provisioned

The stopped old guests remain protected and retain all original storage and snapshot
references:

- VM 110 — `RETAINED-STORAGE-BLOCKED-SO-ManagerSearch`
- VM 112 — `RETAINED-STORAGE-BLOCKED-SO-Sensor-Home`
- VM 117 — `RETAINED-STORAGE-BLOCKED-SO-Sensor-Range`

Their automatic-start setting is disabled and their Proxmox protection flag is set.
No old disk was detached, deleted, moved or activated.

Fresh replacement guests were created with new MAC addresses and new disks stored only
on `Das_Boot`:

| VM | Role name | Resources | Interfaces | Fresh disk |
|---|---|---|---|---|
| 210 | `SO-ManagerSearch` | 8 vCPU, 24 GiB RAM | management on `vmbr5` | 400 GiB |
| 212 | `SO-Sensor-Home` | 8 vCPU, 16 GiB RAM | management on `vmbr5`; capture on `vmbr2` | 900 GiB |
| 217 | `SO-Sensor-Range-BlueNet` | 8 vCPU, 16 GiB RAM | management on `vmbr5`; capture on `vmbr3` and `vmbr4` | 900 GiB |

The three QCOW2 files passed `qemu-img check`, and Proxmox reported each disk at the
requested virtual size on `Das_Boot`. The Security Onion
`2.4.211-20260407` ISO matched the publisher's SHA-256 value
`185d8cf49cd3bfdd8876b8dde48343da90804b0c0ec3eadf0ad90d29c55e72b7`.
An isolated temporary interface found no neighbor using the three planned management
addresses before it was removed and its namespace cleanup was verified.

Only replacement manager VM 210 was started. Its official ISO installer accepted the
new local administrator account and entered the automated operating-system installation.
Replacement sensors 212 and 217 remain stopped. Installation start is not manager
health or Security Onion acceptance.

## 2026-10-20 — manager kernel recovery in progress

During the first manager/search configuration run, the Security Onion ISO's default
Oracle UEK kernel `5.15.0-318.199.3.2.1.el9uek.x86_64` crashed in the
memory-control-group path while the official Elastic Fleet setup was creating
integration policies. Kdump retained the crash evidence under `/var/crash`. The guest
then restarted automatically; this was the source of the operator-visible return to a
login prompt.

The guest has fixed memory with Proxmox ballooning disabled, so the failure was not
treated as a memory-resize event. The default boot entry was changed to the alternate
Red Hat compatible kernel `5.14.0-611.45.1.el9_7.x86_64` already shipped on the same
verified Security Onion ISO. No outside package or custom kernel was added. After
reboot, the manager completed its automatic highstate. Elasticsearch HTTPS returned
401 to an unauthenticated request, showing that its authentication endpoint responded;
Kibana status returned 200. The official Fleet setup progressed beyond the operation
that triggered the crash and remains in progress.

This is a reversible test-range compatibility deviation. The UEK kernel and crash
record remain available for diagnosis. Manager acceptance remains open until Fleet
setup finishes successfully, all expected services pass status checks, a full highstate
finishes without failures, the web login is verified, and restart stability is shown.
Neither sensor has been started.

## 2026-10-20 — host firmware stability gate

The manager's Elasticsearch container later exited with code 134 after the bundled
OpenJDK 25 process received `SIGSEGV` in `libjvm.so`. No out-of-memory kill was
recorded: Docker reported `OOMKilled=false`, the guest kernel recorded no
out-of-memory event, and about 16 GiB remained available. The JVM error report was
copied out of the stopped container before any recovery attempt.

The Proxmox host reports an Intel Core i9-14900KF, MSI PRO B760-P WIFI DDR4
motherboard, BIOS `1.A0` dated 2024-03-28 and CPU microcode `0x123`. Intel's published
13th/14th-generation desktop instability guidance recommends Intel Default Settings
and the latest BIOS containing microcode `0x12F` or later. MSI publishes newer BIOS
releases for this exact board. Outdated host firmware is a material stability concern,
but neither crash has been proven to originate from it; guest software, memory and
other hardware causes remain unresolved.

No firmware was changed remotely. Any firmware maintenance requires a separate
host-wide plan that inventories and protects every running guest, preserves the
unhealthy shared storage without activating it, provides recovery access and verifies
the resulting BIOS settings and microcode. Security Onion manager acceptance and
sensor setup are halted until that maintenance is complete and the manager passes
repeated service, load and restart checks. Both sensors remain stopped, and the failed
manager state and crash records are preserved for diagnosis. A successful firmware
update alone will not establish stability.

After the Elasticsearch crash, the still-running Fleet process was installing optional
packages against an unavailable search service. That run was stopped with termination
status 143 to prevent further failed package writes. The manager then completed an
orderly operating-system shutdown. Proxmox confirms that the manager and both sensors
are stopped and that automatic start remains disabled for all three replacement guests.
