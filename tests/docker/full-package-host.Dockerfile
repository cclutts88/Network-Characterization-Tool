FROM nct-update-host-acceptance:local
RUN apt-get update && apt-get install -y --no-install-recommends curl iproute2 && rm -rf /var/lib/apt/lists/*
