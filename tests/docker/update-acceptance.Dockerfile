# Local acceptance only. Never used as a Range release image.
FROM nct-r23-test-runner:latest
ARG BUILD_ID=nct-update-acceptance-old
ARG BUILD_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ENV NCT_BUILD_ID=${BUILD_ID} NCT_BUILD_COMMIT=${BUILD_COMMIT} NCT_APP_VERSION=0.16.0-update-test
WORKDIR /app
COPY app /app/app
COPY scripts /app/scripts
COPY tests/docker/update_worker_probe.py /app/update_worker_probe.py
CMD ["uvicorn", "update_worker_probe:app", "--host", "0.0.0.0", "--port", "8080"]
