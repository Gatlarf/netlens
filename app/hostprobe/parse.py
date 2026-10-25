"""The answers of the probes as one structure (the same for Linux and Windows), and the comparison of two of them.

A snapshot:
  {"platform": "linux", "partial": false, "mounts": [{"mount": "/", "fs": "ext4", "size": B, "used": B,
       "dirs": [{"path", "bytes"}], "files": [{"path", "bytes", "mtime"}]}],
   "docker": {"usage": [{"type", "total", "active", "bytes", "reclaimable"}], "containers": [{"name", "status", "layer_bytes", "log_bytes", "restarts"}]},
   "deleted": [{"path", "bytes", "process"}]}
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_DIRS = 45
MAX_FILES = 25
UNITS = {"B": 1, "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4, "KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3, "TIB": 1024 ** 4}


class ProbeError(Exception):
    pass


def docker_size(text: str) -> int:
    """'1.2GB', '512kB', '0B' or '1.2GB (virtual 3GB)' (Docker's own units: kB, MB, GB are powers of 1000)."""
    m = re.match(r"\s*([\d.]+)\s*([A-Za-z]+)", text or "")
    if not m:
        return 0
    try:
        return int(float(m.group(1)) * UNITS.get(m.group(2).upper(), 1))
    except ValueError:
        return 0


def _int(text: Any) -> int:
    try:
        return int(float(str(text).strip()))
    except ValueError:
        return 0


def _sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("##"):
            current = line[2:].strip()
            out.setdefault(current, [])
        elif current is not None and line.strip():
            out[current].append(line.rstrip("\n"))
    return out


def parse_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    if "end" not in sec:
        raise ProbeError("the answer from the host was cut off")
    mounts: dict[str, dict] = {}
    for line in sec.get("df", [])[1:]:
        parts = line.split(None, 6)
        if len(parts) == 7:
            mounts[parts[6]] = {"mount": parts[6], "fs": parts[1], "size": _int(parts[2]) * 1024, "used": _int(parts[3]) * 1024, "dirs": [], "files": []}
    for key, lines in sec.items():
        if key.startswith("du "):
            m = mounts.setdefault(key[3:], {"mount": key[3:], "fs": "", "size": 0, "used": 0, "dirs": [], "files": []})
            for line in lines:
                kb, _, path = line.partition("\t")
                if path and kb.strip().isdigit():
                    m["dirs"].append({"path": path, "bytes": int(kb) * 1024})
        elif key.startswith("big "):
            m = mounts.setdefault(key[4:], {"mount": key[4:], "fs": "", "size": 0, "used": 0, "dirs": [], "files": []})
            for line in lines:
                size, _, rest = line.partition("\t")
                mtime, _, path = rest.partition("\t")
                if path and size.strip().isdigit():
                    m["files"].append({"path": path, "bytes": int(size), "mtime": int(float(mtime or 0))})
    docker: dict[str, Any] = {"usage": [], "containers": []}
    for line in sec.get("dockerdf", []):
        p = line.split("|")
        if len(p) >= 5:
            docker["usage"].append({"type": p[0], "total": _int(p[1]), "active": _int(p[2]), "bytes": docker_size(p[3]), "reclaimable": docker_size(p[4])})
    layers = {}
    status = {}
    for line in sec.get("dockerps", []):
        p = line.split("|")
        if len(p) >= 3:
            layers[p[0]] = docker_size(p[2])
            status[p[0]] = p[1]
    logs = {}
    for line in sec.get("dockerlogs", []):
        p = line.split("|")
        if len(p) >= 3:
            logs[p[0].lstrip("/")] = (_int(p[1]), _int(p[2]))
    for name in sorted(set(layers) | set(logs)):
        docker["containers"].append({"name": name, "status": status.get(name, ""), "layer_bytes": layers.get(name, 0), "log_bytes": logs.get(name, (0, 0))[0], "restarts": logs.get(name, (0, 0))[1]})
    deleted = []
    for line in sec.get("deleted", []):
        p = line.split("|", 2)
        if len(p) == 3 and p[0].strip().isdigit():
            deleted.append({"path": p[2].replace(" (deleted)", ""), "bytes": int(p[0]), "process": p[1]})
    for m in mounts.values():
        m["dirs"] = m["dirs"][:MAX_DIRS]
    version = next((int(k.split()[1]) for k in sec if k.startswith("version ") and k.split()[1].isdigit()), None)
    return {"platform": "linux", "script_version": version, "partial": False, "mounts": sorted((m for m in mounts.values() if m["dirs"] or m["files"]), key=lambda m: -m["used"]), "docker": docker, "deleted": deleted[:10]}


def parse_windows(text: str) -> dict[str, Any]:
    at = text.find("##netlens-probe")
    if at < 0:
        raise ProbeError("the answer from the host was cut off")
    try:
        data = json.loads(text[at + len("##netlens-probe"):].strip())
    except ValueError:
        raise ProbeError("the answer from the host could not be read") from None
    if not isinstance(data, dict):
        raise ProbeError("the answer from the host could not be read")

    def many(v):
        return v if isinstance(v, list) else ([v] if isinstance(v, dict) else [])

    mounts = []
    for v in many(data.get("vols")):
        mid = str(v.get("id") or "")
        size, free = _int(v.get("size")), _int(v.get("free"))
        mounts.append({"mount": mid, "fs": "ntfs", "size": size, "used": max(0, size - free), "dirs": [], "files": []})
    for d in many(data.get("dirs")):
        path = str(d.get("p") or "")
        for m in mounts:
            if path.upper().startswith(m["mount"].upper()):
                m["dirs"].append({"path": path.rstrip("\\") if len(path) > 3 else path, "bytes": _int(d.get("s"))})
                break
    for f in many(data.get("big")):
        path = str(f.get("p") or "")
        for m in mounts:
            if path.upper().startswith(m["mount"].upper()):
                m["files"].append({"path": path, "bytes": _int(f.get("s")), "mtime": _epoch(str(f.get("m") or ""))})
                break
    for m in mounts:
        m["dirs"] = sorted(m["dirs"], key=lambda x: -x["bytes"])[:MAX_DIRS]
    return {"platform": "windows", "partial": bool(data.get("partial")), "mounts": mounts, "docker": {"usage": [], "containers": []}, "deleted": []}


def _epoch(text: str) -> int:
    from datetime import datetime

    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


# ----------------------------------------------------------------------------- comparing two snapshots
def _sep(path: str) -> str:
    return "\\" if "\\" in path and "/" not in path else "/"


def _parent(path: str) -> str:
    cut = path.rstrip("/\\")
    return cut[: max(cut.rfind("/"), cut.rfind("\\"))] or path[:1]


def compare(old: dict[str, Any], new: dict[str, Any], min_bytes: int = 200 * 1024 ** 2) -> dict[str, Any]:
    """What grew between two snapshots: directories (the deepest one that explains the growth), big files that appeared, Docker logs and layers."""
    growth: list[dict[str, Any]] = []
    old_mounts = {m["mount"]: m for m in old.get("mounts", [])}
    for m in new.get("mounts", []):
        before = old_mounts.get(m["mount"])
        if before is None:
            continue
        prev = {d["path"]: d["bytes"] for d in before["dirs"]}
        floor = min(prev.values(), default=0)                       # a directory below the cut of the old list was at most this big
        rows = []
        for d in m["dirs"]:
            delta = d["bytes"] - prev.get(d["path"], floor if prev else 0)
            if delta >= min_bytes:
                rows.append({"path": d["path"], "bytes": delta, "now": d["bytes"], "kind": "directory", "new": d["path"] not in prev})
        for r in rows:                                             # a parent whose growth a child explains is not the cause, the child is
            kids = [k for k in rows if k is not r and _parent(k["path"]) == r["path"]]
            if kids and max(k["bytes"] for k in kids) >= 0.8 * r["bytes"]:
                continue
            growth.append({**r, "mount": m["mount"]})
        known = {f["path"]: f["bytes"] for f in before["files"]}
        for f in m["files"]:
            delta = f["bytes"] - known.get(f["path"], 0)
            if delta >= min_bytes:
                growth.append({"path": f["path"], "bytes": delta, "now": f["bytes"], "kind": "file", "new": f["path"] not in known, "mount": m["mount"], "mtime": f.get("mtime")})
    before_c = {c["name"]: c for c in old.get("docker", {}).get("containers", [])}
    for c in new.get("docker", {}).get("containers", []):
        b = before_c.get(c["name"], {"log_bytes": 0, "layer_bytes": 0})
        for key, what in (("log_bytes", "log"), ("layer_bytes", "layer")):
            delta = c[key] - b[key]
            if delta >= min_bytes // 4:
                growth.append({"path": c["name"], "bytes": delta, "now": c[key], "kind": f"container {what}", "new": c["name"] not in before_c, "mount": "docker"})
    growth.sort(key=lambda g: -g["bytes"])
    used_delta = {m["mount"]: m["used"] - old_mounts[m["mount"]]["used"] for m in new.get("mounts", []) if m["mount"] in old_mounts and m["used"]}
    return {"growth": growth[:8], "used_delta": used_delta}


def nice_bytes(n: float) -> str:
    for unit, size in (("TB", 1024 ** 4), ("GB", 1024 ** 3), ("MB", 1024 ** 2), ("kB", 1024)):
        if abs(n) >= size:
            return f"{n / size:.1f} {unit}"
    return f"{int(n)} B"
