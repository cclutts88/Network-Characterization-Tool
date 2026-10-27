FROM docker:dind AS dockercli
FROM nct-r23-test-runner:latest
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /workspace
