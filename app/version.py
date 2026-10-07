"""Application version.

The image is built with NETLENS_VERSION=<major.minor>.<commit count>, so the
patch number rises with every commit. Running from source falls back to a dev tag.
"""

import os

VERSION = os.environ.get("NETLENS_VERSION", "").strip() or "0.2.0-dev"
