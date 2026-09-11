from __future__ import annotations

import os


APP_VERSION = os.environ.get("NCT_APP_VERSION") or "0.12.0-dev"
BUILD_COMMIT = os.environ.get("NCT_BUILD_COMMIT") or "uncommitted"
BUILD_ID = os.environ.get("NCT_BUILD_ID") or f"{APP_VERSION}+{BUILD_COMMIT[:12]}"
