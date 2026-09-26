# NCT Interface Information Architecture

This document is the source of truth for the enterprise interface and the future Operator Guide. The guide must explain this structure; it must not invent a second workflow.

## Analyst journey

1. **Collect evidence** — retain device configurations and Nmap observations with ownership, scope, safety, and execution context.
2. **Identify systems** — reconcile every attained hostname by IP while preserving each source and the analyst's selected identity.
3. **Analyze the current network** — combine retained host, service, interface, route, policy, NAT, object, neighbor, and identity evidence.
4. **Compare changes** — compare like-for-like scan or device collections without rewriting historical evidence.
5. **Investigate and explain** — hunt across the combined evidence, evaluate supported paths and proposed changes, and visualize the resulting topology.

Evidence is collected once and reused. A downstream page must link a conclusion back to retained evidence and must not imply that opening the page contacted the network.

## Navigation and focused workspaces

### Collect

- **Device collections**
  - New collection: plan and execute an accountable, read-only vendor collection.
  - Upload configuration: retain an existing result without contacting a device.
  - WAN designation: review inferred WAN interfaces and save operator-confirmed gateway evidence.
  - Collection history: reopen retained collections instead of repeating access.
- **Nmap scans**
  - Saved Networks: define reusable authorized scope and operational naming before scanning.
  - No-Strike exclusions: establish the shared addresses that every scan path must omit.
  - New scan: start with a Saved Network, durable scan name, and profile; keep protocol, timing, and other scan behavior in a collapsed advanced section.
  - Active scans: monitor the current run and pending submissions in execution order. New Scan does not duplicate this workspace.
  - Scan profiles: manage reusable, versioned collection behavior.
  - Schedules: manage repeatable collections pinned to an exact profile version.
  - Scan history: reopen and organize completed evidence, or copy retained settings into a future run without altering the original record.

### Identify

- **Hostname evidence**
  - Evidence overview: summarize names already present in retained evidence.
  - DHCP and DNS evidence: prepare and import authoritative server output.
  - Hostname Upload: retain mission-partner or analyst-provided names as a distinct source.
  - Review hostnames: compare candidates by IP and choose the identity used elsewhere in NCT.

### Analyze

- **Current network**
  - Host inventory: consolidated current network evidence.
  - LFA: Least Frequency Analysis of peer-relative service and behavior outliers, with an analyst-adjustable 1–50% frequency threshold (20% by default).
  - Import Nmap evidence: retain existing XML without another scan.
- **Network devices**
  - Device overview: select retained device evidence and review identity and coverage.
  - Command activity: review collected commands and volatile responses.
  - Interfaces and routes: inspect path and topology evidence.
  - Policy, NAT and objects: inspect the controls and translations used by Reach.

### Compare

- **Changes over time**
  - Scan comparisons: compare compatible network scans.
  - Device configurations: compare two collections from the same device.

### Investigate

- **Hunt**
  - Network evidence, filters, systems, offline exploit matches, and focused scan review.
- **Reach**
  - Path assessment, proposed policy, proposed route, and exposure reports.
- **Map**
  - Network map: omit the redundant page heading, keep the evidence inventory pinned at the top, and use a compact main-page strip for the current layout name, save/load actions, and parked/hidden object counts. Reserve the canvas for topology interaction.
  - Files and export: inspect retained map sources or export the current presentation without covering the canvas.
  - Map FAQ: explain presentation behavior without implying a network or evidence change.
  - WAN gateway evidence: review the retained evidence that orients the map.

### Workspace

- **Notes**: personal analyst notes remain separate from shared retained evidence.

## Operator Guide rules

- The guide is off by default and is enabled or disabled in the account and settings menu.
- The guide occupies roughly half the screen height and can be snapped to the upper-right or lower-right corner. While open, the Guide tab stays attached to the pane's destination-facing right edge: lower-right for the upper pane and upper-right for the lower pane.
- The guide dock control uses a small pane symbol with the destination corner emphasized rather than an ambiguous arrow. Its accessible label still states whether the guide will move to the top or bottom.
- Guidance assumes a qualified network analyst who is new to NCT.
- Every explanation answers: what this does, what evidence it uses or creates, where that evidence is retained, and which later workspaces consume it.
- Guidance is contextual and non-blocking. It may update on task selection, focus, or hover, but it must never start network activity or change evidence.
- Tool-specific consequences take priority over generic help. For example, Scan name guidance explains how the name appears in history and later selectors; profile guidance explains version pinning.
- Navigation changes and workspace changes require matching guide updates in the same change. Nmap guidance follows the prerequisite order: Saved Networks, No-Strike exclusions, New Scan, active work, reusable profiles and schedules, then retained history.
- Instructions are written only after the related workspace and dependencies are stable and validated.

## Appearance and analyst preferences

- The enterprise shell is the only primary navigation. Retired horizontal navigation and Analyze sub-navigation must not be rendered.
- Graphite SOC is the professional default. The Theme Workshop also offers curated professional, retro, cyber, fun, DCC-inspired, and seasonal American holiday starting points plus personal themes. Holiday themes use recognizable but non-blocking details such as lights, fireworks, spider webs, spring eggs, service ribbons, and harvest geometry. Page panels, controls, tables, notes, map controls, and guide surfaces inherit the selected palette; evidence status colors remain distinct where they carry meaning.
- Operators may tune spacing, panel shape, typography, colors, glow, motion amount, scanlines, transparency, and background effects. Each decorative effect identifies its relative resource cost, animation respects the operating system's reduced-motion preference, and Performance Mode disables every decorative effect without changing the chosen colors or workspace style.
- Personal themes appear before curated themes. In authenticated mode an analyst may publish a copied snapshot to the shared theme library; later private edits do not silently change that shared copy.
- Achievements recognize successful operator milestones without affecting evidence, scoring, permissions, or network activity. The achievement menu and pop-up announcements are visible only while a DCC theme is active; milestones earned under a professional theme are remembered quietly for later. Pop-ups can be muted without losing the achievement history.
- With authentication enabled, theme, guide state, guide corner, sidebar state, and achievement notification preference are private to the signed-in analyst account and follow that analyst between sessions.
- With authentication disabled, those same preferences are stored only in the current browser.
- Expandable sidebar groups use one disclosure arrow on the right. Content panels may use their own left-side disclosure marker without affecting navigation.

## Compact visual language

- Dense summaries and the planned evidence timeline use recognizable symbols instead of repeatedly spelling out the metric type: a workstation for hosts and a network jack for ports.
- Counts and change direction remain visible beside the symbol, such as `+2` or `-3`; color reinforces meaning but is never the only distinction.
- Every symbol retains a tooltip and an accessible text label so an analyst never has to guess what it means.
- Tables, filters, evidence explanations, and other places where precision matters continue to use words.
