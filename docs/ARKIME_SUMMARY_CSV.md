# Arkime communication-summary intake

Use this path when you have a small aggregate of observed traffic but do not have
packet capture or individual Arkime session records. Open **Collect / Arkime /
Communication summaries**, then use **Import communication summary**.

This first Tier A adapter accepts the NCT-defined **Arkime Summary CSV v1** contract.
It is not a native Arkime export format. Prepare a UTF-8 CSV whose header is exactly:

```text
source_ip,destination_ip,destination_port,transport,detected_protocol,vlan,session_count,packet_count,byte_count
```

Every row must contain a valid destination IP and at least one count. `source_ip`,
`destination_port`, `transport`, `detected_protocol`, `vlan`, and individual count
columns may be blank when the source summary does not know them. Supported transports
are TCP, UDP, SCTP, ICMP, and ICMPv6. Zero is retained as zero; a blank count remains
Unknown. A file may contain at most 10,000 rows and 10 MiB.

Before upload, record the exact Network Scope, observation point, query start and end,
Arkime time-bounding rule, query expression, summary basis, export assessment, and
capture coverage. Use **All matching groups** only when the export includes every group
for the stated query. Use **Top-N** for ranked or limited exports and enter the saved
limit. Use **Unknown** when you cannot establish how the source selected its groups.
Top-N and Unknown summaries cannot be called complete.
NCT checks these declarations for contradictions, but the aggregate rows do not contain
an authoritative matching total or per-row timestamps. NCT therefore cannot
independently verify that every group is present or that every row belongs inside the
declared time window.

Choose **Validate and retain summary**. NCT validates the complete file before it
publishes any database receipts. Accepted files keep their exact bytes and one
immutable receipt per source row. Uploading identical bytes may reuse the same
content-addressed copy, but every upload remains a separate observation with its own
operator, scope, observation point, window, declarations, and row receipts.
Receipt APIs return retained counts as exact decimal text so a browser cannot round a
large 64-bit value while displaying it.

The retained view calls the address and port fields **Observed destination** and
**Reported destination port**. Traffic addressed to a port does not prove that the
port accepted the traffic, is listening, or remains open. NCT does not add counts
across repeated or overlapping files, create current hosts or services, calculate
Last Seen, or feed these summaries into Hunt, Reach, Map, or current-state conclusions.
An empty retained summary does not prove that no traffic occurred.

Use **Download exact CSV** to verify the retained source. If the source bytes or
storage path no longer match the saved SHA-256 receipt, NCT refuses the download.
Opening or paging retained summaries reads NCT's saved receipts only and does not
contact Arkime or the network.

