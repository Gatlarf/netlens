"""Write the Netlens API reference (markdown) from the application's own OpenAPI description.

    python tools/api_reference.py > api-reference.md

Endpoints are grouped by the first part of their path; the summary is the first line of the handler's docstring.
"""
import os
import sys
import tempfile
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NETLENS_API_DOCS", "on")
os.environ.setdefault("NETLENS_TOKEN", "x")
os.environ["NETLENS_DATA_DIR"] = tempfile.mkdtemp()

from app.config import load_settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.version import VERSION  # noqa: E402


def main() -> None:
    spec = create_app(load_settings()).openapi()
    groups: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for path, ops in sorted(spec["paths"].items()):
        parts = [p for p in path.split("/") if p]
        group = (parts[1] if len(parts) > 1 and parts[0] == "api" else (parts[0] if parts else "root")).split(".")[0].replace("-", " ")
        for method, op in ops.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            text = (op.get("description") or op.get("summary") or "").strip().splitlines()
            first = text[0].strip() if text else ""
            if first.lower() == path.strip("/").replace("/", " ").lower():
                first = ""
            groups[group].append((method.upper(), path, first.replace("|", "/")))
    out = ["Every Netlens page uses this API, so anything you can do in the web interface you can script. "
           "Send the token as `Authorization: Bearer <token>`. Create tokens under **Settings, Users and tokens**; make them **read-only** for monitoring tools. "
           "Reading needs a viewer, changing needs an administrator. Prometheus numbers are at `/metrics`, and `/api/health` needs no token.", "",
           f"This reference lists {sum(len(v) for v in groups.values())} endpoints, generated from the current release. "
           "To browse it interactively, start Netlens with `NETLENS_API_DOCS=on` and open `/docs`.", ""]
    for group in sorted(groups):
        out += [f"## {group}", "", "| Method | Path | What it does |", "|---|---|---|"]
        out += [f"| {m} | `{p}` | {t} |" for m, p, t in sorted(groups[group], key=lambda r: (r[1], r[0]))]
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
