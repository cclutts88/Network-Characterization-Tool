# Private-lab HTTPS setup

The Network Characterization Tool requires HTTPS before it will accept an interactive SSH password. For isolated ranges, each Tool server uses its own private lab certificate and operators trust that server's public lab certificate once.

## New Tool server

1. Give the server a stable IP address.
2. From the repository directory, run `sh scripts/setup-lab-https.sh SERVER_IP`, replacing `SERVER_IP` with the Tool server address.
3. Open `http://SERVER_IP/nct-lab-root.crt` on each operator workstation to download the public lab certificate.
4. In Windows, open the downloaded certificate, choose **Install Certificate**, select **Current User**, place it in **Trusted Root Certification Authorities**, and accept the trust warning.
5. Close and reopen the Tool page at `https://SERVER_IP/`.

The HTTP page redirects operators to HTTPS. Port 8080 remains bound only to the Tool server's loopback interface for local diagnostics.

## Certificate handling

- Never commit `certs/`, `tls/`, `caddy-data/`, or `caddy-config/`.
- Never copy a private key to an operator workstation.
- The downloadable `nct-lab-root.crt` is public trust material; the matching CA private key remains on the Tool server.
- The setup script refuses to overwrite existing keys. Back up the Tool server before replacing or renewing certificates.
- A different server IP requires a new server certificate and a new one-time trust step for its lab CA.
