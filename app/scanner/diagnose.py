"""Why can't nmap do raw scans in this container? Looks at what the container really has, so the message can say which setting is wrong.

The usual causes, in the order they are checked: the capabilities are not in the container's bounding set (cap_add missing or the container was not
re-created), no-new-privileges is on, the interface nmap wants is not visible (no host network), or the file capabilities that the image puts on
nmap are not there at run time (some storage drivers and file systems, for example on a Synology, drop them): then nmap, which runs as a normal user,
has no rights even though the container has them. The last one has only a weaker work-around: run the container as root with `user: "0:0"` and add DAC_OVERRIDE
to `cap_add`, so that root can still write the data folder (without it the app cannot start). That puts NET_ADMIN on the whole app instead of only nmap.
"""

from __future__ import annotations

import errno
import os
import re
import shutil
from pathlib import Path
from typing import Any

CAP_NET_ADMIN, CAP_NET_RAW = 12, 13


def _status() -> dict[str, str]:
    out = {}
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            key, _, value = line.partition(":")
            out[key] = value.strip()
    except OSError:
        pass
    return out


def _has(hexmask: str | None, bit: int) -> bool | None:
    try:
        return bool(int(hexmask or "", 16) >> bit & 1)
    except ValueError:
        return None


def nmap_file_capability() -> bool | None:
    """Does the nmap binary still carry its file capability? None when this cannot be told."""
    path = shutil.which("nmap")
    if not path:
        return None
    try:
        os.getxattr(os.path.realpath(path), "security.capability")
        return True
    except OSError as exc:
        if exc.errno == errno.ENODATA:
            return False
        return None


def interfaces() -> list[str]:
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def diagnose(error_text: str = "") -> dict[str, Any]:
    """What this container has, and the most likely reason raw scans fail. `findings` are plain sentences, `cause` is the first thing to fix."""
    st = _status()
    bounding, effective = st.get("CapBnd"), st.get("CapEff")
    raw, admin = _has(bounding, CAP_NET_RAW), _has(bounding, CAP_NET_ADMIN)
    root = os.geteuid() == 0
    eff_raw = _has(effective, CAP_NET_RAW)
    no_new = st.get("NoNewPrivs") == "1"
    file_cap = nmap_file_capability()
    named = re.search(r"failed to open device ([\w.@-]+)", error_text, re.I)
    wanted = named.group(1) if named else None
    nics = interfaces()
    findings: list[str] = []
    cause = None
    if raw is False or admin is False:
        missing = " and ".join(n for n, ok in (("NET_RAW", raw), ("NET_ADMIN", admin)) if ok is False)
        cause = f"The container does not have {missing}. Add cap_add: [NET_RAW, NET_ADMIN] to the netlens service and re-create the container."
    elif no_new:
        cause = "The container runs with no-new-privileges, which stops nmap from using its capabilities. Remove security_opt: no-new-privileges and re-create the container."
    elif wanted and nics and wanted not in nics:
        cause = f"The interface {wanted} is not visible inside the container: it is not using the host network. Add network_mode: host and re-create the container."
    elif not root and file_cap is False:
        cause = ("The container has NET_RAW and NET_ADMIN, but the file system under it dropped the capability that the image puts on nmap, and nmap runs as a normal "
                 "user. (Some storage set-ups do this; it does not happen on a current Synology DSM 7.2 with Container Manager 24, where the standard file works.) Work-around, weaker than the default: add user: \"0:0\" to the netlens service AND DAC_OVERRIDE "
                 "to its cap_add list, then re-create it. Without DAC_OVERRIDE a root container cannot write its data folder. Read the README (Troubleshooting) for what this costs.")
    elif not root and eff_raw is False and file_cap is None:
        cause = "The container has the capabilities, but nmap, running as a normal user, did not get them. Try running the container as root: add user: \"0:0\" to the netlens service and re-create it."
    findings.append(f"Container capabilities: NET_RAW {'yes' if raw else 'no' if raw is False else '?'}, NET_ADMIN {'yes' if admin else 'no' if admin is False else '?'}")
    findings.append(f"Running as {'root' if root else 'a normal user (uid %d)' % os.geteuid()}; no-new-privileges {'ON' if no_new else 'off'}")
    findings.append(f"nmap file capability: {'present' if file_cap else 'MISSING' if file_cap is False else 'unknown'}")
    if nics:
        findings.append(f"Network interfaces seen: {', '.join(nics[:12])}" + (f" ({wanted} {'is' if wanted in nics else 'is NOT'} among them)" if wanted else ""))
    return {"cause": cause, "findings": findings, "root": root, "file_capability": file_cap, "bounding": {"NET_RAW": raw, "NET_ADMIN": admin}, "no_new_privileges": no_new}
