"""The container's health check: asks /api/health over http, then over https (Netlens serves https itself when it has a certificate; the certificate is not checked
here, the question is only whether the server answers)."""

import os
import ssl
import sys
import urllib.request


def main() -> int:
    port = os.environ.get("NETLENS_BIND", "0.0.0.0:8080").split(":")[-1]
    context = ssl._create_unverified_context()          # noqa: S323 - local call to ourselves
    for scheme in ("http", "https"):
        try:
            with urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/api/health", timeout=4, context=context if scheme == "https" else None) as response:   # noqa: S310
                if response.status == 200:
                    return 0
        except Exception:      # noqa: BLE001 - try the other scheme
            continue
    return 1


if __name__ == "__main__":
    sys.exit(main())
