# Private-lab HTTPS setup

The Network Characterization Tool requires HTTPS before it will accept an interactive SSH password. For isolated ranges, each Tool server uses its own private lab certificate and operators trust that server's public lab certificate once.

## New Tool server

1. Give the server a stable IP address. If operators will use a local DNS name, create that record before installation.
2. Run `sudo sh scripts/install-nct.sh` and choose HTTPS plus **generate** when prompted. Enter the optional operator DNS name when one is configured. The installer creates TLS material under `nct-deployment/tls-material`, approves both the server IP and that name, validates the certificate, and deploys only after its separate preflight and approval.
3. Transfer the public `nct-deployment/tls-material/certs/nct-lab-root.crt` to each operator workstation through the approved process. Do not transfer either private key.
4. In Windows, open the transferred certificate, choose **Install Certificate**, select **Current User**, place it in **Trusted Root Certification Authorities**, and accept the trust warning.
5. Close and reopen the verified HTTPS address printed by the installer.

Do not use the browser's proceed-anyway option. If a browser warning remains, stop
and verify that the DNS name resolves to this server, the certificate includes that
exact name, and the public CA certificate is installed in the trusted-root store.

The analyzer stays inside the Docker network when the HTTPS proxy is used. Only
the chosen host HTTPS address and port are published.

## Certificate handling

- Never commit `nct-deployment`, certificates, keys, or proxy runtime state.
- Never copy a private key to an operator workstation.
- The transferable `nct-lab-root.crt` is public trust material; the matching CA private key remains on the Tool server.
- Certificate generation never starts or rebuilds containers and refuses to overwrite existing TLS material. Back up the Tool server before replacing or renewing certificates.
- A different server IP or DNS name requires a server certificate that approves the new address. If the lab authority also changes, operator workstations need the new public authority through the approved trust process.
