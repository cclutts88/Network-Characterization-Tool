FROM nct-update-acceptance:new
ENV NCT_BUILD_ID=nct-update-acceptance-failed NCT_BUILD_COMMIT=cccccccccccccccccccccccccccccccccccccccc
RUN printf 'raise RuntimeError("isolated update acceptance failure")\n' > /app/app/main.py
