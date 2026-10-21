"""Application version.

The image is built with NETLENS_VERSION=<major.minor>.<commits since VERSION changed> (contrib/version.sh), so the patch number rises
with every commit. The number is written into the image as a file (app/BUILD_VERSION) and that file wins: the environment variable of
the same name is only used when there is no file (running from source). Why: tools such as Portainer copy every variable of a running
container, including the ones the old image set, into the new container, so an update kept reporting the old version, and since the
version is also the cache key of the interface files, the browser kept showing the old interface as well.
"""

import os
from pathlib import Path


def _baked() -> str:
    try:
        return (Path(__file__).parent / "BUILD_VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


BAKED = _baked()
FROM_ENV = os.environ.get("NETLENS_VERSION", "").strip()
VERSION = (BAKED if BAKED and BAKED != "dev" else "") or FROM_ENV or "0.2.0-dev"
STALE_ENV = bool(BAKED and BAKED != "dev" and FROM_ENV and FROM_ENV != BAKED)   # the container carries an old NETLENS_VERSION
