# Private-lab HTTPS setup

The Network Characterization Tool requires HTTPS before it will accept an interactive SSH password. For isolated ranges, each Tool server uses its own private lab certificate and operators trust that server's public lab certificate once.

## New Tool server

1. Give the server a stable IP address.
2. Run `sudo sh scripts/install-nct.sh` and choose HTTPS plus **generate** when prompted. The installer creates TLS material under `nct-deployment/tls-material`, validates it, and deploys only after its separate preflight and approval.
3. Transfer the public `nct-deployment/tls-material/certs/nct-lab-root.crt` to each operator workstation through the approved process. Do not transfer either private key.
4. In Windows, open the transferred certificate, choose **Install Certificate**, select **Current User**, place it in **Trusted Root Certification Authorities**, and accept the trust warning.
5. Close and reopen the verified HTTPS address printed by the installer.

The analyzer stays inside the Docker network when the HTTPS proxy is used. Only
the chosen host HTTPS address and port are published.

## Certificate handling

- Never commit `nct-deployment`, certificates, keys, or proxy runtime state.
- Never copy a private key to an operator workstation.
- The transferable `nct-lab-root.crt` is public trust material; the matching CA private key remains on the Tool server.
- Certificate generation never starts or rebuilds containers and refuses to overwrite existing TLS material. Back up the Tool server before replacing or renewing certificates.
- A different server IP requires a new server certificate and a new one-time trust step for its lab CA.
