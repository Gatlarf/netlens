"""Turn low-level scan failures into messages a user can act on."""

from __future__ import annotations

_RULES: list[tuple[tuple[str, ...], str]] = [
    (
        ("operation not permitted", "permission denied", "requires root", "dnet:", "errno 1", "errno 13"),
        "A container setting is missing: nmap could not run because the container lacks the NET_RAW and NET_ADMIN capabilities "
        "(or the host network). Add cap_add: [NET_RAW, NET_ADMIN] and network_mode: host to the netlens service (Portainer: Network = host, "
        "Capabilities = NET_RAW + NET_ADMIN), without no-new-privileges, and re-create the container. See Troubleshooting in the README.",
    ),
    (
        ("nmap not found", "no such file or directory: 'nmap'", "errno 2"),
        "nmap is not installed (or not on PATH) in this environment.",
    ),
    (
        ("timed out",),
        "The scan timed out. Try a smaller range under Settings, or scan again later.",
    ),
    (
        ("no scan ranges",),
        "There is nothing to scan: no scan ranges are set and none could be detected. "
        "Set a range under Settings → Scan ranges (or NETLENS_RANGES), and make sure the container uses host networking.",
    ),
    (
        ("no targets were specified", "failed to resolve"),
        "nmap was given no valid targets. Check the scan ranges under Settings.",
    ),
    (
        ("interrupted by restart",),
        "The scan was interrupted because Netlens restarted.",
    ),
]


def is_capability_error(exc: BaseException | str) -> bool:
    """Is this the failure of a container that was started without NET_RAW / NET_ADMIN (or without the host network)?"""
    lowered = (exc.strip() if isinstance(exc, str) else str(exc)).lower()
    return any(n in lowered for n in _RULES[0][0])


def explain_scan_error(exc: BaseException | str) -> str:
    """Return a friendly message for a scan failure, keeping the original text as detail."""
    raw = str(exc).strip() or exc.__class__.__name__ if not isinstance(exc, str) else exc.strip()
    lowered = raw.lower()
    for needles, message in _RULES:
        if any(n in lowered for n in needles):
            return f"{message} (detail: {raw})" if raw and raw.lower() not in message.lower() else message
    return raw or "The scan failed for an unknown reason."
