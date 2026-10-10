# Writing Netlens plugins

Netlens can learn about your network from other systems through **plugins**. A plugin talks to one kind of device
(a router, a hypervisor, ...) and hands Netlens the result in a fixed format. Two kinds exist today:

| Kind | Reports | Examples |
| :--- | :--- | :--- |
| `hypervisor` | hosts, and the VMs/containers that run on them | Proxmox VE (built in), ESXi, Hyper-V, libvirt |
| `dns` | a DNS server that Netlens writes device names and addresses to | Technitium DNS (more welcome: BIND with RFC 2136, Pi-hole, AdGuard Home, dnsmasq) |
| `topology` | network nodes (router, switch, access point, mesh node) and the clients connected to them | ASUS AiMesh (built in), Omada, UniFi, Fritz!Box, MikroTik |

Plugin API version: **1**.

## How plugins work

A plugin only **fetches** data. It never touches Netlens' database or the map. Netlens validates what the plugin
returns, matches the entries to the devices it has scanned (by MAC address, then IP address), writes the links, and
shows them on the map, the Hierarchy page and the device pages. Each plugin can be switched on or off in
**Settings -> Plugins**, and gets its own settings page that Netlens builds from the plugin's `plugin.json`, so a
plugin needs no user-interface code.

## Quick start

1. In **Settings -> Plugins** press **Download example plugin** (or `GET /api/plugins/example.zip`).
2. Edit `plugin.json` (name, id, settings fields) and `plugin.py` (replace the made-up data in `fetch()` with a call to your device).
3. Zip `plugin.json` and `plugin.py` (at the top of the zip, or together inside a single folder).
4. **Settings -> Plugins -> Upload plugin**. The plugin starts **off**.
5. Open its settings page, fill in the form and press **Test connection**. When it works, tick **Enable** and **Save**. Netlens syncs at once and after every scan.
6. Add a `diagnose(config)` (see below) before you share the plugin: it lets testers send you a report of what their device answers.

To change a plugin, upload the new zip again; Netlens asks whether to replace it and keeps its settings.

## Package layout

```
my-router/            (the folder is optional)
  plugin.json         the manifest (required)
  plugin.py           the code (required)
  helper.py           more modules, optional (import them as usual)
```

- Limits: zip at most 2 MB, 8 MB unpacked, 200 files.
- File names: letters, digits, `_`, `-`, `.` and spaces. No hidden files, links or paths containing `..`.
- Uploading **never runs** the code. `plugin.py` is only checked for syntax and for the two required functions.
- The `id` must not be the id of a built-in plugin (`proxmox`, `asus`).
- Uploaded plugins are stored in the data volume (`<data dir>/plugins/<id>/`) and survive container updates.
- Built-in plugins cannot be removed, only switched off. An uploaded plugin can be removed (this deletes its files and settings).

## plugin.json reference

| Field | Required | Meaning |
| :--- | :--- | :--- |
| `id` | yes | 2-31 characters: lowercase letters, digits, `-`, `_`; starts with a letter. Must equal the folder name once installed. |
| `name` | yes | Shown in the menu and plugin list (max 60). |
| `version` | yes | Like `1.0.0`. |
| `api_version` | yes | Must be `1`. |
| `kind` | yes | `hypervisor` or `topology`. |
| `description` | no | A sentence or two (max 500). |
| `author`, `homepage` | no | Shown in the plugin list. |
| `timeout` | no | Seconds, 5-600, default 60. Netlens stops the plugin after this long. |
| `diagnose` | no, but recommended | `true` when `plugin.py` has `diagnose(config)`: the plugin's page then shows a **Run diagnostic** button (see below). |
| `config` | no | The settings form: a list of fields (below). |

### Settings fields (`config`)

| Field | Meaning |
| :--- | :--- |
| `key` | Required. Lowercase letters, digits, `_`, starts with a letter, max 32, unique. The key in the `config` dict your code receives. |
| `type` | `text` (default), `password`, `bool`, `number` or `select`. |
| `label`, `help`, `placeholder` | Texts in the form. |
| `section` | Optional heading; fields with the same section are grouped. |
| `required` | The plugin cannot be switched on until every required field is filled (ignored for `bool`). |
| `default` | Initial value. |
| `min`, `max` | For `number`. |
| `options` | For `select`: a list of strings or `{"value": ..., "label": ...}`. The first is the default. |

`password` fields are secrets: they are masked in the interface and the API, and leaving the field blank when saving keeps the saved value.

### Example

```json
{
  "id": "example-router",
  "name": "Example router",
  "version": "1.0.0",
  "api_version": 1,
  "kind": "topology",
  "author": "Your name",
  "description": "Template plugin: reports a made-up router with one access point and two clients. Replace fetch() with a call to your own router.",
  "timeout": 30,
  "config": [
    {
      "key": "host",
      "type": "text",
      "label": "Router address",
      "placeholder": "192.168.0.1",
      "required": true,
      "help": "Shown in the settings form Netlens builds from this file."
    },
    {
      "key": "username",
      "type": "text",
      "label": "Username"
    },
    {
      "key": "password",
      "type": "password",
      "label": "Password"
    },
    {
      "key": "verify_tls",
      "type": "bool",
      "label": "Verify TLS certificate",
      "default": false
    }
  ]
}
```

## plugin.py: `test(config)` and `fetch(config)`

Netlens calls two **top-level, normal (not `async`)** functions. `config` is a dict holding every key of `plugin.json`
(passwords as plain text).

- `test(config)` runs when the user presses **Test connection**. Return `{"message": "text to show"}` (the message is optional) or raise an exception. It must not change anything on your device and Netlens saves nothing.
- `fetch(config)` runs after every scan and when the user presses **Sync now**. Return a dict in the format of your plugin's kind (see below).

Your code runs in a separate Python process (`python -I`) with only the plugin folder importable, a stripped environment (no `NETLENS_*` variables) and no database path. **Use only the Python standard library** (`urllib`, `json`, `ssl`, `socket`, `re`, ...); packages cannot be installed. Anything printed is ignored.

```python
"""Example Netlens plugin (kind "topology").

Netlens runs this file in its own process and calls two functions, each with the settings the user typed
into the form (the keys come from "config" in plugin.json):

    test(config)   -> {"message": "text shown after Test connection"}
    fetch(config)  -> the data described in PLUGINS.md for your plugin's kind

Raise an exception with a clear message when something goes wrong; Netlens shows it to the user. If the
login was refused, set `auth_failed = True` on the exception so Netlens stops retrying until the user acts
(this protects the account from being locked). Use only the Python standard library.
"""


class LoginRefused(Exception):
    auth_failed = True


def _connect(config):
    if not config.get("host"):
        raise ValueError("enter the router address")
    # Replace this with a real request to your device, for example with urllib.request.
    # if the password is wrong:  raise LoginRefused("login refused (check the username and password)")
    return {"host": config["host"]}


def test(config):
    _connect(config)
    return {"message": "Connected to the example router: 1 access point, 2 clients"}


def fetch(config):
    _connect(config)
    return {
        "nodes": [
            {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.0.1", "name": "Router", "role": "gateway"},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.0.2", "name": "Access point", "role": "ap",
             "parent_mac": "aa:bb:cc:00:00:01"},
        ],
        "clients": [
            {"mac": "11:22:33:44:55:01", "ip": "192.168.0.50", "name": "Laptop", "node_mac": "aa:bb:cc:00:00:02",
             "medium": "wifi", "band": "5 GHz"},
            {"mac": "11:22:33:44:55:02", "ip": "192.168.0.51", "name": "Printer", "node_mac": "aa:bb:cc:00:00:01",
             "medium": "wired"},
        ],
    }
```

### `diagnose(config)`: please include it

Nobody can test a plugin on every device, firmware or version. A `diagnose(config)` lets a tester press **Run diagnostic** on your plugin's settings page in Netlens and send you a
report of what their device answered, without running any script. **Every plugin should have one**: it is what turns "it does not work" into a fix. Add `"diagnose": true` to
`plugin.json` and a function that returns a dictionary:

```python
def diagnose(config):
    controller = connect(config)             # a refused login raises the same exceptions as test(): it must not retry either
    report = {"steps": {}}
    try:
        report["controller_version"] = controller.version
        for name, call in (("devices", controller.devices), ("clients", controller.clients)):
            try:
                rows = call()
                report["steps"][name] = {"ok": True, "count": len(rows), "first": [describe(r) for r in rows[:3]]}
            except Exception as exc:               # record the step that failed and go on with the others
                report["steps"][name] = {"ok": False, "error": str(exc)[:300]}
        result = fetch(config)                    # what the plugin makes of it, as counts
        report["result"] = {"nodes": len(result["nodes"]), "clients": len(result["clients"])}
    finally:
        controller.logout()
    return report
```

Netlens runs `diagnose(config)` in the same isolated process as `test()` and `fetch()`, with the values in the form, and shows the report in a box to **copy or download**.
Rules for what goes in it:

- Describe the **shape** of what the device returned: field names, types, counts, and a few harmless enumerations (`type`, `status`...). **Never content**: no names, addresses, MAC addresses, serial numbers or free text.
  Copy this helper (it replaces numbers, MAC and IP addresses and text by placeholders):

```python
import re


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in ("type", "status", "state"):  # words that are the same on every device and help to understand the data
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
            return "<mac " + ("dashes" if "-" in value else "colons") + ">"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"
```

- Record which **step failed and why** (without addresses) and carry on with the other steps, so one report shows everything that is wrong. Raise your usual exceptions for a refused login.
- Log in **once**, like `fetch()`, and log out again.
- Keep the report small (a few hundred KB at most).
- Netlens removes the values of the plugin's own settings (addresses, user names, keys, passwords) and every MAC address from the report before showing it. That is a second line of defence, not a licence to send content.

`python plugin-index/tools/check_plugin.py <plugin> --config cfg.json` runs your `diagnose()` too, and prints a note when a plugin has none.

## Errors and refused logins

- Raise any exception. Its text (cut at 500 characters) is shown to the user.
- If the **login was refused**, set `auth_failed = True` on the exception (a class attribute is fine). Netlens then stops calling the plugin automatically until the user saves its settings or presses **Sync now**, so a wrong password cannot get an account locked. Never retry a failed login in a loop.
- A crash, a timeout, output that is not JSON and output that breaks the format are all reported in the plugin's status. The last good data and links stay on the map.

## Output for kind `hypervisor`

Return `{"hosts": [...], "guests": [...]}`.

| Host field | Required | Meaning |
| :--- | :--- | :--- |
| `id` | yes | Text or number, unique. |
| `name` | no | Default: the id. |
| `ip` | no | IPv4 address. |
| `mac` | no | MAC address. |
| `online` | no | `true` (default) or `false`. |

| Guest field | Required | Meaning |
| :--- | :--- | :--- |
| `id` | yes | Text or number, unique. |
| `name` | no | Default: the id. |
| `kind` | no | Text such as `vm`, `lxc`, `qemu`. Default `vm`. |
| `host_id` | no | Must be the `id` of an entry in `hosts`. |
| `status` | no | Text such as `running`. Default `unknown`. |
| `macs` | no | List of MAC addresses of the guest's network cards. |
| `ips` | no | List of IPv4 addresses. |

```json
{
  "hosts": [
    {"id": "pve1", "name": "pve1", "ip": "192.168.0.180", "online": true}
  ],
  "guests": [
    {"id": "100", "name": "web", "kind": "lxc", "host_id": "pve1", "status": "running",
     "macs": ["bc:24:11:aa:bb:cc"], "ips": ["192.168.0.50"]}
  ]
}
```

## Output for kind `topology`

Return `{"nodes": [...], "clients": [...]}`. A *node* is a router, switch, access point or mesh node; a *client* is a device connected to one.

| Node field | Required | Meaning |
| :--- | :--- | :--- |
| `mac` | yes | Unique. |
| `macs` | no | Extra MAC addresses of the same device (for example other radios). |
| `ip` | no | IPv4 address. |
| `name` | no | Default: the MAC. |
| `model` | no | Free text. |
| `role` | no | `gateway`, `switch`, `ap` or `node` (default). **At most one** node may be the `gateway` (the main router). |
| `parent_mac` | no | The `mac` (or one of the `macs`) of the node this one is connected to. Without it, the node hangs below the gateway. |

| Client field | Required | Meaning |
| :--- | :--- | :--- |
| `mac` | yes | The client's MAC address. |
| `ip` | no | IPv4 address. |
| `name` | no | Free text. |
| `node_mac` | no | The `mac` (or one of the `macs`) of the node it is connected to. Without it, the client hangs below the gateway. |
| `medium` | no | `wired`, `wifi` or `unknown` (default). |
| `band` | no | Text such as `5 GHz`. |
| `rssi` | no | Wi-Fi signal in dBm (a whole number from -127 to 0). Netlens stores one sample per sync and shows signal history and roaming. |
| `tx_mbps`, `rx_mbps` | no | Current Wi-Fi link rate in Mbit/s (numbers, 0 or more). |
| `vendor` | no | The manufacturer as the router knows it. If it is really a DHCP vendor class (`MSFT 5.0`, `android-dhcp-13`), Netlens recognises that and uses it as the operating system. |
| `os` | no | The operating system, if the router has fingerprinted it (`Windows 11`, `Android 13`). |
| `model` | no | A model or product name (`iPhone14,2`, `Chromecast`). |
| `port` | no | The switch port a wired client is plugged into (`Gi1/0/5`, up to 60 characters). Netlens shows it on the device page next to the node's name. |
| `device_type` | no | One of `router`, `switch`, `ap`, `server`, `pc`, `phone`, `tablet`, `tv`, `speaker`, `console`, `appliance`, `printer`, `iot`, `camera`, `nas`, `vm`. Any other value is ignored. |

The last four are evidence, not facts: Netlens weighs them against what its own scans found, and the device page shows why it chose a type. Only send what the router actually knows; leave a field out rather than guessing.

```json
{
  "nodes": [
    {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.0.1", "name": "Router", "role": "gateway"},
    {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.0.2", "name": "Access point", "role": "ap",
     "parent_mac": "aa:bb:cc:00:00:01"}
  ],
  "clients": [
    {"mac": "11:22:33:44:55:01", "ip": "192.168.0.50", "name": "Laptop",
     "node_mac": "aa:bb:cc:00:00:02", "medium": "wifi", "band": "5 GHz"}
  ]
}
```

General rules for both kinds: MAC addresses are `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff` in any case (Netlens stores them in lower case); IP addresses are dotted IPv4; each list may hold at most 5000 entries; the result must be JSON (dict, list, str, int, float, bool, None).

## How Netlens uses the output

- **Matching.** Hosts and nodes are matched to scanned devices by IP then MAC (nodes: MAC first, then IP). Hypervisor guests: by MAC first, then IP. A host is never taken for a guest and a device is claimed only once. Entries Netlens has not scanned are simply not shown (they appear once a scan finds them).
- **Links.** A `hypervisor` plugin creates `host-of` links (guest below host). A `topology` plugin creates `uplink` links (client below node, node below its parent). These are the strongest *automatic* sources for the network hierarchy: hypervisor links first, then uplinks, then traceroute and default-gateway guesses. A parent you set by hand always wins, and a link you delete on the map stays deleted.
- **Device pages.** Hypervisor plugins add a *Virtualization* box (the guest's host, or a host's guests). A topology plugin that reports `rssi` for Wi-Fi clients adds a *Wi-Fi* card (signal history, node, roaming).
- **Names.** A client's `name` becomes an alias of the matching device (source `router`); a device that has no hostname of its own shows it.
- **Turning a plugin off** removes its links and guests from the map and keeps its settings. **Turning it on** syncs immediately.

## Publishing your plugin

Plugins can be listed in the **plugin index** so that other people can find and install them under *Settings → Browse plugins*.
Include a `diagnose(config)` (see above) so that people who try your plugin can report problems with one click. Release your plugin as a zip on GitHub, check it with `plugin-index/tools/check_plugin.py` (a copy of the Netlens repository is
enough; it runs the same checks Netlens runs), and submit an entry by pull request. Reviewers read the code and set the review level
(*Verified*, *Reviewed* or *Community*). The whole process, the entry format and a plugin template are in
`plugin-index/README.md` in the Netlens repository.

## Limits and security

An uploaded plugin is **Python code that runs inside the Netlens container** with the rights of the application.
Netlens isolates it as well as it reasonably can: its own process, a stripped environment, no database path, a time
limit, and validation of everything it returns. **This is not a sandbox**: the plugin runs as the same operating-system
user and could read the data volume, which holds the database with saved credentials. So:

- Only install plugins from sources you trust, and read the code first.
- Uploading needs the Netlens login. A freshly uploaded plugin stays **off** until you switch it on, and the upload shows the file's SHA-256 so you can compare it with the author's.
- Give a plugin the least privileged account your device offers (read-only where possible).

## Troubleshooting

| Message | What to do |
| :--- | :--- |
| `plugin.json: ...` / `... is the id of a built-in plugin` | Fix the manifest as the message says; choose another id. |
| `plugin.py must define a top-level function test(config)` | Define both `test(config)` and `fetch(config)`, not `async`. |
| `the plugin did not answer within N seconds` | Make the plugin faster, or raise `timeout` (max 600). |
| `the plugin crashed (...)` | Run the code outside Netlens and look at the traceback; remember only the standard library is available. |
| `the plugin returned data that does not follow the contract: guests[0].host_id: ...` | The path at the start names the offending field; fix it as described in the tables above. |
| `the plugin returned data that is not JSON` | Return plain dicts, lists, strings and numbers (no sets, bytes or custom objects). |
| `not configured yet: ...` | Fill in the required fields on the plugin's settings page. |
| Status says automatic syncing is paused | The login was refused (`auth_failed`). Fix the credentials, then **Save** or **Sync now**. |


## DNS plugins (kind `dns`)

A DNS plugin lets Netlens register devices in a DNS server. Netlens does the thinking (which names and addresses should exist, what is already
there, what is safe to change, the preview and the approval); the plugin only talks to the server. Unlike the other kinds it also **writes**, so
its page says so, and nothing is written before the administrator approves it (or switches on automatic mode).

**Entry points** (all `def f(config)`, except `apply`):

* `test(config)` returns `{"message": ...}`, as always.
* `fetch(config)` returns a **snapshot** of the server: `{"zones": [{"name": "home.example.com", "kind": "forward", "writable": true}, ...],
  "records": [{"zone": ..., "name": "nas.home.example.com", "type": "A", "value": "192.168.0.7", "ttl": 3600, "managed": true, "comment": "..."}],
  "server": "dns1"}`. Types are `A`, `AAAA`, `PTR` (value = the target name) and `CNAME`. `writable` says whether this account can write the zone
  (a secondary zone is not writable). Include the reverse zones (`...in-addr.arpa`) you find. Names are compared in lower case without a final dot.
  `managed` is true when the record carries Netlens' marker.
* `apply(config, changes)` gets a list of changes and returns `[{"id": ..., "ok": true|false, "error": "..."}]`, one per change. A change is
  `{"id", "action": "add"|"update"|"delete", "zone", "name", "type", "value", "old_value", "comment"}`: `value` is the new value, `old_value` the
  current one of an update, `comment` the marker to put on the record. Write A and PTR records exactly as given (the reverse record is a separate
  change). Do not send a TTL unless the server needs one: the zone default is wanted.

Netlens adds two settings next to the user's: `zones` (the forward zones to read) and `marker` (the comment that marks Netlens' own records).

**Rules for authors** (they protect other people's DNS): put the marker on every record you write and report it back as `managed`; select the exact
record to update or delete by its current value so a record that changed meanwhile is not overwritten; before an add, check that the name still has
no record; never fall back to writing on a read-only (secondary) server; and report a refused login with `auth_failed`.

The manifest may list `"capabilities": ["marker", "delete"]` (the server can mark records, and can remove them). `technitium` in `plugins/` is a
complete example, and `tests/fake_technitium.py` shows how to test one against a simulated server.

### Guest details (hypervisor plugins)

A guest may carry `details`, an object Netlens stores and shows on the device page: `image`, `project`, `service`, `health`,
`started`, `network`, `network_driver` (text), `restarts`, `exit_code` (numbers), `exposed`, `restarting` (yes/no) and `ports`
(a list of `{container_port, host_port, proto, bind}`). Unknown keys are dropped. The Docker plugin uses them for containers.
