# Set up the Arkime API connector on an isolated Range

This guide connects one NCT installation to one Arkime Viewer. The connection is
read-only: NCT asks Arkime for a bounded list of session records and retains the exact
JSON response as evidence. It does not retrieve packet captures or change Arkime.

Complete these steps as the Range administrator. An NCT analyst cannot create the
Arkime account or install the certificate from the NCT interface.

## Before you begin

You need:

- the Arkime Viewer address and port;
- an Arkime administrator who can create one dedicated account;
- an HTTPS certificate whose name or IP matches the address NCT will use;
- the public certificate of the authority that issued that certificate; and
- root access to the NCT server.

The connector refuses plain HTTP, redirects and certificates it cannot verify. Do not
work around a certificate problem by disabling verification.

## 1. Give Arkime Viewer a trusted HTTPS certificate

Arkime Viewer uses `certFile` and `keyFile` in its active configuration. The normal
configuration file is `/opt/arkime/etc/config.ini`. Put both settings in the section
used by the Viewer, commonly `[default]`:

```ini
certFile=/opt/arkime/etc/tls/arkime-viewer.crt
keyFile=/opt/arkime/etc/tls/arkime-viewer.key
```

The certificate must include the DNS name or IP address that will appear in
`NCT_ARKIME_API_URL`. Restart only the Viewer after the certificate and key have been
installed, then run:

```sh
systemctl is-active arkimeviewer
ss -ltn | grep ':8005 '
```

Success prints `active` and one listening entry for port 8005. Keep the private key on
the Arkime server. Only the public CA certificate in PEM format is copied to NCT.

## 2. Create the dedicated Arkime account

Sign in to Arkime with an account that can manage users. Open the user administration
page and create this account:

| Field | Value |
| --- | --- |
| User ID | `nct-reader` |
| Display name | `NCT read-only connector` |
| Enabled | On |
| Web access | Off, so the account is API-only |
| Role | `arkimeUser` only |
| Remove or scrub permission | Off |
| Packet-search or hunt permission | Off |
| Administrator roles | None |

Use a unique password generated for this connector. Do not reuse an Arkime
administrator, OpenSearch or NCT login. Arkime's `arkimeUser` role is the minimum
standard Viewer role; Arkime does not provide a role limited to only the Sessions API.
NCT itself enforces the narrower behavior by calling only `GET /api/sessions` and by
refusing redirects.

If user administration is performed from the Arkime server instead, use the installed
Arkime user-management command for that Arkime version, assign only `arkimeUser`, and
then verify the same settings in the Arkime user page. Do not use the `--admin` option
for the NCT account.

## 3. Verify the account from the NCT server

Copy the public Arkime CA certificate in PEM format to the NCT server as a file named
`arkime-ca.pem`. On the Arkime server, print the certificate's X.509 SHA-256
fingerprint:

```sh
openssl x509 -in /PATH/TO/ARKIME_CA.pem -noout -fingerprint -sha256
```

On the NCT server, print the transferred copy's fingerprint:

```sh
openssl x509 -in /root/arkime-ca.pem -noout -fingerprint -sha256
```

The complete fingerprint lines must match exactly. This compares the certificate,
not merely its filename. Then run this from the NCT server, replacing only
`ARKIME_ADDRESS`. The first two lines create a ten-minute window using Unix epoch
seconds, which is the time format Arkime expects:

```sh
stop_epoch=$(date +%s)
start_epoch=$((stop_epoch - 600))
curl --fail --silent --show-error --digest \
  --user 'nct-reader' \
  --cacert /root/arkime-ca.pem \
  "https://ARKIME_ADDRESS:8005/api/sessions?startTime=$start_epoch&stopTime=$stop_epoch&length=1&facets=0"
```

Enter the connector password when prompted. Success returns JSON with a `data` array.
An authentication error means the account or password is wrong. A certificate error
means the address, certificate name or trusted CA is wrong; correct that before
continuing. Success is a JSON response containing a `data` array, even when that array
is empty for the selected window.

## 4. Install the two connector secrets on the NCT server

Run these commands as root. They ask for the password without displaying it or placing
it in shell history:

```sh
install -d -m 0700 /var/lib/nct/arkime-secrets
install -m 0400 /root/arkime-ca.pem /var/lib/nct/arkime-secrets/ca.pem
read -r -s -p 'Arkime nct-reader password: ' arkime_password
printf '\n'
printf '%s' "$arkime_password" > /var/lib/nct/arkime-secrets/password
unset arkime_password
chmod 0400 /var/lib/nct/arkime-secrets/password
```

The password and CA files are mounted read-only into the NCT container. The password
is not stored in a pull definition or evidence record.

## 5. Save the non-secret connector settings

Create `/var/lib/nct/deployment/arkime-connector.env` with root-only permissions:

```sh
install -d -m 0700 /var/lib/nct/deployment
cat > /var/lib/nct/deployment/arkime-connector.env <<'EOF'
NCT_ARKIME_API_ENABLED=1
NCT_ARKIME_API_URL=https://ARKIME_ADDRESS:8005
NCT_ARKIME_API_USERNAME=nct-reader
NCT_ARKIME_API_TIMEOUT_SECONDS=30
NCT_ARKIME_SECRETS_DIR=/var/lib/nct/arkime-secrets
EOF
chmod 0600 /var/lib/nct/deployment/arkime-connector.env
```

Replace `ARKIME_ADDRESS` with the exact name or IP in the Arkime certificate. Do not
put credentials, query text or a trailing API path in the URL.

## 6. Attach the connector to the NCT Compose deployment

Use only a verified connector-capable NCT package. Its manifest must include
`compose.arkime.yaml`, and its image must contain the connector module. Older packages
must not be extended by copying this one file into them.

Keep `NCT_WORKDIR` set to the verified, extracted connector-capable package directory.
The following block reads the current container's actual deployment values and refuses
to continue if the container was not created by Compose or any required value is
missing. It then renders the replacement configuration before recreating NCT:

```sh
cd "$NCT_WORKDIR"
sha256sum -c PACKAGE-MANIFEST.sha256 || exit 1
grep -q 'compose.arkime.yaml' PACKAGE-MANIFEST.sha256 || {
  echo 'HALT: this is not a connector-capable package' >&2
  exit 1
}
docker exec nct python -c 'import app.arkime_connector' || {
  echo 'HALT: the running NCT image does not contain the Arkime connector' >&2
  exit 1
}

export NCT_IMAGE="$(docker inspect nct --format '{{.Config.Image}}')"
export NCT_BIND_ADDRESS="$(docker inspect nct --format '{{(index (index .HostConfig.PortBindings "8445/tcp") 0).HostIp}}')"
export NCT_HTTPS_PORT="$(docker inspect nct --format '{{(index (index .HostConfig.PortBindings "8445/tcp") 0).HostPort}}')"
export NCT_DATA_DIR="$(docker inspect nct --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}')"
nct_cert_source="$(docker inspect nct --format '{{range .Mounts}}{{if eq .Destination "/run/tls/nct-server.crt"}}{{.Source}}{{end}}{{end}}')"
export NCT_TLS_ROOT="$(dirname "$(dirname "$nct_cert_source")")"
export NCT_BOOTSTRAP_DIR="$(docker inspect nct --format '{{range .Mounts}}{{if eq .Destination "/run/nct-bootstrap"}}{{.Source}}{{end}}{{end}}')"
export NCT_PROJECT="$(docker inspect nct --format '{{index .Config.Labels "com.docker.compose.project"}}')"

for required_value in NCT_IMAGE NCT_BIND_ADDRESS NCT_HTTPS_PORT NCT_DATA_DIR NCT_TLS_ROOT NCT_BOOTSTRAP_DIR NCT_PROJECT; do
  eval "value=\${$required_value}"
  [ -n "$value" ] || {
    echo "HALT: could not recover $required_value from the current Compose deployment" >&2
    exit 1
  }
done
[ -d "$NCT_DATA_DIR" ] && [ -f "$NCT_TLS_ROOT/tls/nct-server.crt" ] && [ -f "$NCT_TLS_ROOT/tls/nct-server.key" ] || {
  echo 'HALT: the current data or TLS mounts do not match the recovered deployment values' >&2
  exit 1
}

set -a
. /var/lib/nct/deployment/arkime-connector.env
set +a
docker compose -p "$NCT_PROJECT" --project-directory "$NCT_WORKDIR" \
  -f compose.range.yaml -f compose.arkime.yaml config >/tmp/nct-compose-check.txt
grep -Fq '/run/nct-arkime' /tmp/nct-compose-check.txt || {
  echo 'HALT: Arkime secret mount is missing from the composed configuration' >&2
  exit 1
}
grep -Fq "$NCT_DATA_DIR" /tmp/nct-compose-check.txt || {
  echo 'HALT: the composed data mount does not match the current deployment' >&2
  exit 1
}
docker compose -p "$NCT_PROJECT" --project-directory "$NCT_WORKDIR" \
  -f compose.range.yaml -f compose.arkime.yaml up -d --no-deps --force-recreate nct
curl --connect-timeout 2 --max-time 5 -kfsS \
  "https://$NCT_BIND_ADDRESS:$NCT_HTTPS_PORT/health"
docker exec nct python -c 'from app.build_info import BUILD_ID; print(BUILD_ID)'
docker inspect nct --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
docker logs --since 5m nct
```

Do not paste the password into the Compose file or environment file. A future NCT
upgrade must include this same Arkime override and environment file when it recreates
the container. After recreation, confirm the NCT health endpoint, build identity,
`/data` mount and analyst login before creating a pull definition. Success means the
health command returns JSON, the expected connector-capable build is printed, the same
saved data directory still points to `/data`, and the recent log has no repeated
startup error.

## 7. Verify the connector in NCT

1. Sign in to NCT as an administrator.
2. Open **Collect → Arkime → Passive evidence intake**.
3. Confirm the page says the automatic connector is available.
4. Create a disabled pull definition first. Select one active Network Scope, enter an
   observation-point label, set cadence to 60 minutes, lookback to 10 minutes, overlap
   to 0 minutes and collection delay to 60 seconds. Leave the expression blank unless
   a reviewed filter is required. Leave **Start automatic pulls after saving**
   unchecked.
5. Select **Pull now** and wait for the saved result.
6. Confirm the attempt shows its exact time window, sensor label, returned count,
   completeness and a link to the retained source.
7. Download the exact source and confirm the receipt identifies Arkime, the selected
   scope and the same time window.
8. Count the acceptance pull as successful only when it is **Complete** and shows the
   expected scope, observation-point label, time window, returned count and downloadable
   exact source. Retain Partial or Unknown results for review, but do not accept them as
   a successful connector test.
9. Enable the scheduled definition only after the manual pull succeeds.

The first Range acceptance pull is limited to 1,000 records and 10 MiB. Partial or
unknown results are retained for review and pause that definition. Opening or
refreshing the page reads NCT's saved records and does not contact Arkime.

## Troubleshooting order

1. Confirm Arkime Viewer and OpenSearch are healthy.
2. Confirm the NCT server can reach the exact HTTPS address and port.
3. Re-run the one-row `curl` check with certificate verification enabled.
4. Confirm both secret files exist and are readable inside the NCT container without
   printing their contents:

   ```sh
   docker exec nct sh -c 'test -s /run/nct-arkime/password && test -s /run/nct-arkime/ca.pem && echo ARKIME_SECRET_FILES_READABLE'
   ```

   Success prints `ARKIME_SECRET_FILES_READABLE`.
5. Confirm the NCT connector status is available before creating a pull definition.
6. Review the saved pull attempt. Retry the same window only when the interface offers
   that action; do not create a different window to hide a failed attempt.
7. If NCT does not return to the login page after recreation, repeat the health, build,
   mount and recent-log checks from step 6 before changing any files.

Stop the Range trial if Arkime or OpenSearch crashes, a required service repeatedly
restarts, or the host reports memory, swap, storage, kernel or clock trouble.
