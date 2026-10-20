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
