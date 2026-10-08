# Writing Netlens plugins

Netlens can learn about your network from other systems through **plugins**. A plugin talks to one kind of device
(a router, a hypervisor, ...) and hands Netlens the result in a fixed format. Two kinds exist today:

| Kind | Reports | Examples |
| :--- | :--- | :--- |
| `hypervisor` | hosts, and the VMs/containers that run on them | Proxmox VE (built in), ESXi, Hyper-V, libvirt |
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
