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
