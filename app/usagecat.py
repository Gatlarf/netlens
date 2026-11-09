"""Application categories for the traffic statistics, and the privacy choices around them (see app/usagecfg.py for the on/off switch).

A router reports an application name (often a domain). This module decides what Netlens keeps and shows:

  * detail "names": the name is stored and its category is worked out when the statistics are read;
  * detail "categories": the name is turned into its category before anything is written, so no name reaches the database;
  * a redirect shows a whole category under another label ("Others"), for privacy. The names of a redirected category are never stored, and
    changing a redirect or a rule rewrites what is already stored (``apply_policy``). That cannot be undone.

A category comes from the administrator's own rules first, then from the shipped catalogue below, else "Uncategorised". A pattern is a domain
suffix ("*.tiktok.com") or a keyword ("tiktok", found anywhere in the name, ignoring capitals).
"""

from __future__ import annotations

import sqlite3

from app.db import get_setting, set_setting

DETAIL_KEY = "usage.detail"
DETAILS = ("names", "categories")
UNKNOWN = "Uncategorised"
MAX_LABEL = 40
MAX_RULES = 500

CATALOGUE: dict[str, tuple[str, ...]] = {
    "Social media": ("facebook", "instagram", "twitter", "tiktok", "snapchat", "pinterest", "linkedin", "reddit", "tumblr", "mastodon", "*.threads.net", "fbcdn", "twimg", "*.x.com", "bsky"),
    "Streaming": ("youtube", "googlevideo", "ytimg", "netflix", "nflx", "disneyplus", "hulu", "primevideo", "twitch", "spotify", "*.scdn.co", "deezer", "vimeo", "hbomax", "*.max.com", "plex", "crunchyroll", "dazn", "videoland", "streamz", "soundcloud", "tidal", "iplayer"),
    "Video calls": ("zoom", "*.teams.microsoft.com", "microsoft teams", "webex", "meet.google", "gotomeeting", "skype", "facetime", "bluejeans", "whereby", "jitsi"),
    "Messaging": ("whatsapp", "telegram", "*.signal.org", "discord", "messenger", "*.slack.com", "slack", "viber", "wechat", "*.line.me", "imessage", "element.io"),
    "Gaming": ("steampowered", "steamcommunity", "steamcontent", "epicgames", "xbox", "playstation", "nintendo", "riotgames", "blizzard", "battle.net", "roblox", "minecraft", "*.ea.com", "ubisoft", "*.gog.com", "fortnite", "leagueoflegends"),
    "Adult": ("pornhub", "xvideos", "xnxx", "xhamster", "redtube", "youporn", "onlyfans", "chaturbate", "brazzers", "porn"),
    "Shopping": ("amazon.", "ebay", "aliexpress", "alibaba", "*.bol.com", "zalando", "etsy", "temu", "shein", "coolblue", "paypal", "shopify"),
    "News": ("nytimes", "theguardian", "reuters", "*.nos.nl", "*.hln.be", "*.vrt.be", "standaard.be", "nieuwsblad", "washingtonpost", "cnn.com"),
    "Cloud and backup": ("dropbox", "onedrive", "icloud", "drive.google", "googleusercontent", "*.box.com", "mega.nz", "backblaze", "wasabi", "nextcloud", "sharepoint", "s3.amazonaws", "blob.core.windows", "storage.googleapis"),
    "Software updates": ("windowsupdate", "update.microsoft", "swcdn.apple", "mzstatic", "*.debian.org", "*.ubuntu.com", "docker.io", "docker.com", "ghcr.io", "github", "npmjs", "pypi", "play.googleapis", "*.gvt1.com", "*.adobe.com", "delivery.mp.microsoft"),
    "Smart home and IoT": ("tuya", "*.meethue.com", "sonos", "*.ring.com", "*.nest.com", "tplinkcloud", "*.xiaomi.com", "*.mi.com", "homeassistant", "home-assistant", "shelly", "ecobee", "wyze", "arlo"),
    "VPN and proxy": ("nordvpn", "expressvpn", "protonvpn", "*.proton.me", "tailscale", "zerotier", "mullvad", "wireguard", "openvpn"),
    "Web and search": ("*.google.com", "*.google.be", "*.google.nl", "bing.com", "duckduckgo", "yahoo", "wikipedia", "gmail", "outlook", "office365", "*.microsoft.com", "*.apple.com"),
}
CATEGORIES = tuple(CATALOGUE) + (UNKNOWN,)


def _clean(text: str, what: str, limit: int = MAX_LABEL) -> str:
    text = " ".join((text or "").split())
    if not text:
        raise ValueError(f"{what} cannot be empty")
    if len(text) > limit:
        raise ValueError(f"{what} is too long (at most {limit} characters)")
    return text


def _matches(pattern: str, name: str) -> bool:
    p = pattern.lower()
    if p.startswith("*."):
        suffix = p[1:]
        return name == p[2:] or name.endswith(suffix) or ("." + name).endswith(suffix)
    return p in name


class Policy:
    """Everything needed to turn a reported name into what is kept: loaded once, then used for many names."""

    def __init__(self, conn: sqlite3.Connection):
        self.detail = detail(conn)
        self.redirects = {r["category"]: r["label"] for r in conn.execute("SELECT category, label FROM usage_redirects")}
        # the administrator's own rules win, longest pattern first (the most specific)
        self.rules = [(r["pattern"], r["category"]) for r in conn.execute("SELECT pattern, category FROM usage_rules ORDER BY LENGTH(pattern) DESC, id")]
        self.labels = set(self.redirects.values())
        self.known = {c.lower(): c for c in {*CATEGORIES, *(c for _, c in self.rules)}}

    def category(self, name: str) -> str:
        """The category of something a router reported, or of a value already stored (a category or a redirect label stands for itself)."""
        low = (name or "").strip().lower()
        if name in self.labels:
            return name
        if low in self.known:
            return self.known[low]
        for pattern, category in self.rules:
            if _matches(pattern, low):
                return category
        for category, patterns in CATALOGUE.items():
            if any(_matches(p, low) for p in patterns):
                return category
        return UNKNOWN

    def label(self, category: str) -> str:
        return self.redirects.get(category, category)

    def stored(self, name: str) -> str:
        """What is written to the database for this name."""
        category = self.category(name)
        if category in self.redirects:
            return self.redirects[category]
        return category if self.detail == "categories" else name


def detail(conn: sqlite3.Connection) -> str:
    """The detail kept. Not chosen yet: an install that already holds application names stays on names, a new one starts on categories only."""
    value = get_setting(conn, DETAIL_KEY)
    if value in DETAILS:
        return value
    from app import usagecfg

    value = "names" if usagecfg.stored_rows(conn) else "categories"
    set_setting(conn, DETAIL_KEY, value)
    return value


def categorise(conn: sqlite3.Connection, rows: list[sqlite3.Row] | list[dict], policy: Policy | None = None) -> list[dict]:
    """Rows of ``name, rx, tx`` grouped by category (as shown: a redirected category carries its new label), biggest first."""
    policy = policy or Policy(conn)
    totals: dict[str, list[int]] = {}
    for r in rows:
        label = policy.label(policy.category(r["name"]))
        t = totals.setdefault(label, [0, 0])
        t[0] += r["rx"] or 0
        t[1] += r["tx"] or 0
    grand = sum(a + b for a, b in totals.values())
    return [{"name": n, "rx": a, "tx": b, "share": round(100 * (a + b) / grand, 1) if grand else 0}
            for n, (a, b) in sorted(totals.items(), key=lambda i: -(i[1][0] + i[1][1]))]


def merge(policy: Policy, apps: list[dict]) -> list[dict]:
    """The applications of one report with the policy applied; names that end up the same are added together."""
    out: dict[str, dict] = {}
    for a in apps:
        name = policy.stored(a["name"])
        if name in out:
            out[name]["rx_bytes"] += a["rx_bytes"]
            out[name]["tx_bytes"] += a["tx_bytes"]
        else:
            out[name] = {"name": name, "rx_bytes": a["rx_bytes"], "tx_bytes": a["tx_bytes"]}
    return list(out.values())


def apply_policy(conn: sqlite3.Connection) -> int:
    """Rewrite what is stored so it matches the policy (redirected categories lose their names; "categories only" loses all of them). Returns the
    number of rows that changed. This cannot be undone: the names are gone."""
    policy = Policy(conn)
    changed = 0
    for table, keys in (("app_usage", ("day", "source")), ("client_app_usage", ("day", "source", "device_id"))):
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        wanted: dict[tuple, dict] = {}
        for r in rows:
            name = policy.stored(r["name"])
            key = tuple(r[k] for k in keys) + (name,)
            if key in wanted:
                wanted[key]["rx_bytes"] += r["rx_bytes"]
                wanted[key]["tx_bytes"] += r["tx_bytes"]
                wanted[key]["updated"] = max(wanted[key]["updated"], r["updated"])
            else:
                wanted[key] = {**dict(r), "name": name}
        if len(wanted) == len(rows) and all(policy.stored(r["name"]) == r["name"] for r in rows):
            continue
        changed += len(rows)
        conn.execute(f"DELETE FROM {table}")
        cols = list(rows[0].keys()) if rows else []
        for item in wanted.values():
            conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", [item[c] for c in cols])
    conn.commit()
    return changed


def set_detail(conn: sqlite3.Connection, value: str) -> int:
    if value not in DETAILS:
        raise ValueError("detail must be 'names' or 'categories'")
    set_setting(conn, DETAIL_KEY, value)
    return apply_policy(conn) if value == "categories" else 0


def set_redirect(conn: sqlite3.Connection, category: str, label: str) -> int:
    category = _clean(category, "the category")
    label = _clean(label, "the label")
    if category.lower() == label.lower():
        return clear_redirect(conn, category)
    conn.execute("INSERT INTO usage_redirects (category, label) VALUES (?, ?) ON CONFLICT(category) DO UPDATE SET label = excluded.label", (category, label))
    conn.commit()
    return apply_policy(conn)


def clear_redirect(conn: sqlite3.Connection, category: str) -> int:
    """Stop redirecting. Names that were replaced by the label stay replaced: they were not kept."""
    conn.execute("DELETE FROM usage_redirects WHERE category = ?", (category,))
    conn.commit()
    return 0


def add_rule(conn: sqlite3.Connection, pattern: str, category: str) -> int:
    pattern = _clean(pattern, "the pattern", 80).lower()
    category = _clean(category, "the category")
    if pattern in ("*", "*.") or pattern.startswith("*.") and len(pattern) < 4:
        raise ValueError("that pattern would match too much")
    if conn.execute("SELECT COUNT(*) FROM usage_rules").fetchone()[0] >= MAX_RULES:
        raise ValueError("too many rules")
    conn.execute("INSERT INTO usage_rules (pattern, category) VALUES (?, ?) ON CONFLICT(pattern) DO UPDATE SET category = excluded.category", (pattern, category))
    conn.commit()
    return apply_policy(conn)


def delete_rule(conn: sqlite3.Connection, rule_id: int) -> bool:
    cur = conn.execute("DELETE FROM usage_rules WHERE id = ?", (rule_id,))
    conn.commit()
    return cur.rowcount > 0


def overview(conn: sqlite3.Connection) -> dict:
    policy = Policy(conn)
    unknown: list[dict] = []
    if policy.detail == "names":
        for r in conn.execute("SELECT name, SUM(rx_bytes + tx_bytes) AS n FROM app_usage GROUP BY name ORDER BY n DESC LIMIT 400"):
            if policy.category(r["name"]) == UNKNOWN and r["name"] not in policy.labels and r["name"] != UNKNOWN:
                unknown.append({"name": r["name"], "bytes": r["n"]})
    return {"detail": policy.detail, "categories": list(CATEGORIES), "redirects": [{"category": c, "label": l} for c, l in sorted(policy.redirects.items())],
            "rules": [{"id": r["id"], "pattern": r["pattern"], "category": r["category"]} for r in conn.execute("SELECT id, pattern, category FROM usage_rules ORDER BY category, pattern")],
            "uncategorised": unknown[:15]}
