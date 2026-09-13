# NCT Range compatibility matrix

Run the repeatable, non-destructive baseline from the repository root:

```sh
sh scripts/nct-range-matrix.sh
```

When a specific immutable image is already present, add it to exercise the real
host and image preflight without deploying anything:

```sh
sh scripts/nct-range-matrix.sh --image network-characterization-tool:VERSION
```

The command writes a timestamped report under `nct-deployment`. It performs no
scan, device collection, firewall change, image pull, container swap, or network
device contact. Supplying `--image` still uses the launcher's `--check-only`
path.

## Coverage

| Scenario | Automated baseline | Current disposition |
|---|---|---|
| Compose v2 | Simulated preflight | Supported |
| Legacy Compose v1 | Simulated preflight | Degraded; direct Engine swap |
| Engine without Compose | Simulated preflight | Degraded; supported |
| Minimum/old Docker API | Boundary fixtures | Supported or appliance-required |
| Linux daemon and CPU architecture | Linux/Windows and CPU fixtures | Unsupported hosts fail closed |
| Offline image | Missing, valid, and invalid SHA-256 | Unverified archives fail closed |
| Occupied port | Host-listener fixture | Test/Range select and record an alternate |
| Existing older NCT | Idle and active fixtures | Data retained; active work blocks upgrade |
| Promotion receipt | Match and mismatch fixtures | Exact image/build required |
| `NET_RAW`, packet capture, raw socket, health | Deployment acceptance contract | Failure rolls back deployment |
| Docker bridge/VPN overlap | Not yet automated | Open roadmap control |
| Representative old range hosts | Requires range lab | Record with the generated report |

The matrix item remains open until bridge/VPN overlap detection is implemented
and the same report is captured on representative older range hosts. A passing
developer-host matrix is development evidence, not mission readiness.
