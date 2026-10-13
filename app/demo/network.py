"""The made-up home network of the demo: who is who, how it is wired, what each device does and how reliable it is.

Everything here is fiction (names, addresses, vendors). The layout mirrors a real home lab: a mesh router, managed switches, a
hypervisor with virtual machines and containers, a NAS, cameras, TVs and phones, so every page of Netlens has something to show.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SUBNET = "192.168.42"
DOMAIN = "home.example.net"
REVERSE_ZONE = "42.168.192.in-addr.arpa"

OUI = {
    "ASUSTek Computer": "3c:7c:3f", "TP-Link": "50:c7:bf", "Synology": "00:11:32", "Intel": "a4:bb:6d", "Raspberry Pi Trading": "dc:a6:32",
    "Hikvision": "c0:56:e3", "Reolink": "ec:71:db", "Samsung Electronics": "8c:79:f5", "LG Electronics": "a8:23:fe", "Google": "f4:f5:d8",
    "Apple": "f0:18:98", "Dell": "18:db:f2", "Lenovo": "98:fa:9b", "HP": "3c:d9:2b", "Brother Industries": "00:1b:a9", "Shelly": "e8:db:84",
    "HomeWizard": "5c:cf:7f", "TP-Link Tapo": "b0:95:75", "QEMU": "bc:24:11", "Microsoft": "00:15:5d", "iXsystems": "0c:c4:7a",
    "Ubiquiti": "78:8a:20", "Amazon": "44:65:0d", "Sonos": "5c:aa:fd",
}


@dataclass
class Spec:
    key: str
    name: str
    type: str
    vendor: str
    octet: int
    os: str = ""
    parent: str | None = None          # the device it hangs on (uplink or host)
    link: str | None = None            # "asus" / "snmp" (uplink), "proxmox" / "hyperv" (host-of), None = only the gateway relation
    medium: str = "wired"              # for clients of the mesh: wired or wifi
    ports: tuple = ()                  # (port, service, product)
    profile: str = "normal"            # reliability: solid, normal, flaky, nightly, evening, off
    group: str = ""
    windows: bool = False
    known: bool = True
    notes: str = ""
    custom: str = ""                   # a friendly name set by the owner
    band: str = "5 GHz"


def S(*a, **k) -> Spec:
    return Spec(*a, **k)


WEB = ((80, "http", "nginx"), (443, "https", "nginx"))
SSH = (22, "ssh", "OpenSSH")

DEVICES: list[Spec] = [
    # --- the network itself
    S("gw", "lighthouse", "router", "ASUSTek Computer", 1, "Linux 5.4", None, None, "wired", ((53, "domain", "dnsmasq"), (80, "http", "httpd"), (8443, "https-alt", "")), "solid", "Network", custom="Lighthouse (main router)"),
    S("n_base", "mesh-basement", "router", "ASUSTek Computer", 59, "Linux 4.19", "gw", "asus", "wired", ((80, "http", ""),), "solid", "Network", custom="Mesh node basement"),
    S("n_attic", "mesh-attic", "router", "ASUSTek Computer", 60, "Linux 4.19", "n_base", "asus", "wifi", ((80, "http", ""),), "normal", "Network", custom="Mesh node attic"),
    S("n_guest", "mesh-guestroom", "router", "ASUSTek Computer", 61, "Linux 4.19", "gw", "asus", "wired", ((80, "http", ""),), "solid", "Network", custom="Mesh node guest room"),
    S("n_garage", "mesh-garage", "router", "ASUSTek Computer", 62, "Linux 4.19", "n_guest", "asus", "wifi", ((80, "http", ""),), "flaky", "Network", custom="Mesh node garage"),
    S("sw_rack", "sw-rack", "switch", "TP-Link", 10, "TP-Link SG3428", "gw", "snmp", "wired", ((80, "http", ""), (443, "https", "")), "solid", "Network", custom="Rack switch"),
    S("sw_office", "sw-office", "switch", "TP-Link", 11, "TP-Link SG2210P", "sw_rack", "snmp", "wired", ((80, "http", ""),), "normal", "Network", custom="Office switch (PoE)"),
    S("sw_garden", "sw-garden", "switch", "TP-Link", 12, "TP-Link TL-SG105PE", "n_garage", "snmp", "wired", ((80, "http", ""),), "flaky", "Network", custom="Garden switch"),
    # --- servers and storage
    S("pve", "pve-nuc", "server", "Intel", 30, "Linux 6.8 (Proxmox VE)", "sw_rack", None, "wired", ((22, "ssh", "OpenSSH"), (3128, "http-proxy", ""), (8006, "https", "Proxmox VE")), "solid", "Servers", custom="Proxmox host"),
    S("nas", "truenas", "nas", "iXsystems", 31, "FreeBSD 13", "sw_rack", None, "wired", ((22, "ssh", "OpenSSH"), (80, "http", "nginx"), (443, "https", "nginx"), (445, "microsoft-ds", "Samba"), (2049, "nfs", "")), "solid", "Servers", custom="TrueNAS"),
    S("pbs", "pbs", "server", "Intel", 32, "Linux 6.1", "sw_rack", None, "wired", ((22, "ssh", "OpenSSH"), (8007, "https", "Proxmox Backup")), "nightly", "Servers", custom="Backup server"),
    S("rpi_docker", "rpi-docker", "server", "Raspberry Pi Trading", 33, "Linux 6.6 (Debian 12)", "sw_rack", None, "wired", ((22, "ssh", "OpenSSH"), (2375, "docker", "Docker"), (1883, "mqtt", "Mosquitto")), "normal", "Servers"),
    S("rpi_dns", "rpi-dns2", "server", "Raspberry Pi Trading", 54, "Linux 6.1 (DietPi)", "sw_rack", None, "wired", ((22, "ssh", "OpenSSH"), (53, "domain", "dnsmasq"), (80, "http", "lighttpd")), "normal", "Servers", custom="DNS server 2"),
    S("hv", "forge-hv", "server", "Dell", 41, "Microsoft Windows 11", "sw_office", None, "wired", ((135, "msrpc", ""), (445, "microsoft-ds", ""), (5986, "wsmans", "WinRM")), "normal", "Servers", True, custom="Hyper-V host"),
    S("lab", "lab-server", "server", "Dell", 42, "Linux 5.15 (Ubuntu 22.04)", "sw_office", None, "wired", ((22, "ssh", "OpenSSH"),), "flaky", "Servers"),
    S("build", "build-server", "server", "Lenovo", 43, "Linux 6.5 (Ubuntu 24.04)", "sw_office", None, "wired", ((22, "ssh", "OpenSSH"), (8080, "http-alt", "Jenkins")), "nightly", "Servers"),
    # --- virtual machines on Proxmox and Hyper-V
    S("ha", "ha-core", "vm", "QEMU", 70, "Linux 6.6 (Home Assistant OS)", "pve", "proxmox", "wired", ((22, "ssh", ""), (8123, "http", "Home Assistant")), "solid", "Servers", custom="Home Assistant"),
    S("docker1", "docker-lxc1", "vm", "QEMU", 71, "Linux 6.1 (Debian 12)", "pve", "proxmox", "wired", ((22, "ssh", "OpenSSH"), (2375, "docker", "Docker"), (3000, "http", "Grafana"), (8222, "http", "Vaultwarden")), "solid", "Servers"),
    S("web1", "web-lxc1", "vm", "QEMU", 72, "Linux 6.1 (Debian 12)", "pve", "proxmox", "wired", ((22, "ssh", "OpenSSH"),) + WEB, "solid", "Servers"),
    S("proxy", "proxy-lxc", "vm", "QEMU", 73, "Linux 6.1 (Debian 12)", "pve", "proxmox", "wired", ((22, "ssh", "OpenSSH"), (80, "http", "nginx"), (81, "http", "Nginx Proxy Manager"), (443, "https", "nginx")), "solid", "Servers", custom="Reverse proxy"),
    S("dns1", "dns-lxc1", "vm", "QEMU", 74, "Linux 6.1 (Debian 12)", "pve", "proxmox", "wired", ((22, "ssh", "OpenSSH"), (53, "domain", "Technitium"), (5380, "http", "Technitium")), "solid", "Servers", custom="DNS server 1"),
    S("media", "media-vm", "vm", "QEMU", 75, "Linux 6.1 (Ubuntu)", "pve", "proxmox", "wired", ((22, "ssh", "OpenSSH"), (8096, "http", "Jellyfin")), "normal", "Media"),
    S("testvm", "test-vm", "vm", "QEMU", 77, "Linux 5.15", "pve", "proxmox", "wired", ((22, "ssh", "OpenSSH"),), "off", "Servers", custom="Scratch VM (stopped)"),
    S("hvlab", "hv-lab", "vm", "Microsoft", 78, "Microsoft Windows Server 2022", "hv", "hyperv", "wired", ((3389, "ms-wbt-server", "RDP"), (445, "microsoft-ds", "")), "normal", "Servers", True),
    # --- cameras
    S("cam_front", "cam-front", "camera", "Hikvision", 100, "Linux 3.18", "sw_office", None, "wired", ((80, "http", ""), (554, "rtsp", ""), (8000, "http-alt", "")), "solid", "Cameras", custom="Front door camera"),
    S("cam_drive", "cam-driveway", "camera", "Hikvision", 101, "Linux 3.18", "sw_office", None, "wired", ((80, "http", ""), (554, "rtsp", "")), "solid", "Cameras", custom="Driveway camera"),
    S("cam_hall", "cam-hall", "camera", "Reolink", 102, "Linux 3.10", "sw_office", None, "wired", ((80, "http", ""), (554, "rtsp", ""), (9000, "cslistener", "")), "normal", "Cameras", custom="Hallway camera"),
    S("cam_garage", "cam-garage", "camera", "Reolink", 103, "Linux 3.10", "sw_office", None, "wired", ((80, "http", ""), (554, "rtsp", "")), "normal", "Cameras", custom="Garage camera"),
    S("cam_back", "cam-back", "camera", "Hikvision", 104, "Linux 3.18", "sw_garden", None, "wired", ((80, "http", ""), (554, "rtsp", "")), "normal", "Cameras", custom="Back garden camera"),
    S("cam_garden", "cam-garden", "camera", "Hikvision", 105, "Linux 3.18", "sw_garden", None, "wired", ((80, "http", ""), (554, "rtsp", "")), "normal", "Cameras", custom="Garden shed camera"),
    S("cam_shed", "cam-shed", "camera", "Reolink", 106, "Linux 3.10", "sw_garden", None, "wired", ((80, "http", ""), (554, "rtsp", "")), "off", "Cameras", custom="Shed camera (unplugged)"),
    S("cam_attic", "cam-attic", "camera", "Reolink", 107, "Linux 3.10", "n_attic", "asus", "wifi", ((80, "http", ""), (554, "rtsp", "")), "flaky", "Cameras", custom="Attic camera", band="2.4 GHz"),
    # --- family devices
    S("pc_anna", "desk-anna", "pc", "Dell", 120, "Microsoft Windows 11", "sw_office", "snmp", "wired", ((135, "msrpc", ""), (445, "microsoft-ds", "")), "normal", "Family", True, custom="Anna's PC"),
    S("pc_ben", "desk-ben", "pc", "Lenovo", 121, "Linux 6.8 (Fedora 40)", "n_base", "asus", "wifi", ((22, "ssh", "OpenSSH"),), "evening", "Family", custom="Ben's workstation"),
    S("pc_guest", "laptop-guest", "pc", "HP", 122, "Microsoft Windows 10", "n_guest", "asus", "wifi", ((445, "microsoft-ds", ""),), "evening", "Family", True, False, custom="Guest laptop"),
    S("tab_k", "tab-kitchen", "tablet", "Samsung Electronics", 125, "Android 14", "n_base", "asus", "wifi", (), "evening", "Family", custom="Kitchen tablet", band="2.4 GHz"),
    S("tab_kids", "tab-kids", "tablet", "Apple", 126, "Apple iPadOS 17", "n_guest", "asus", "wifi", ((62078, "iphone-sync", ""),), "evening", "Family", custom="Kids' tablet"),
    S("ph_anna", "phone-anna", "phone", "Apple", 127, "Apple iOS 17", "n_base", "asus", "wifi", ((62078, "iphone-sync", ""),), "evening", "Family", custom="Anna's phone"),
    S("ph_ben", "phone-ben", "phone", "Samsung Electronics", 128, "Android 14", "n_attic", "asus", "wifi", (), "evening", "Family", known=True, custom="Ben's phone", band="2.4 GHz"),
    # --- media and living room
    S("tv_living", "tv-living", "tv", "LG Electronics", 140, "Linux (webOS)", "sw_office", "snmp", "wired", ((3000, "http", "webOS"), (3001, "https", "")), "normal", "Media", custom="Living room TV"),
    S("tv_bed", "tv-bedroom", "tv", "Samsung Electronics", 141, "Linux (Tizen)", "n_attic", "asus", "wifi", ((8001, "http", ""), (8002, "https", "")), "evening", "Media", custom="Bedroom TV"),
    S("tv_kids", "tv-kids", "tv", "LG Electronics", 142, "Linux (webOS)", "n_guest", "asus", "wifi", ((3000, "http", "webOS"),), "evening", "Media", custom="Kids' TV"),
    S("cast", "chromecast-attic", "tv", "Google", 143, "Linux (Android TV)", "n_attic", "asus", "wifi", ((8008, "http", "Chromecast"), (8009, "ajp13", "")), "normal", "Media", custom="Chromecast", band="2.4 GHz"),
    # --- small things
    S("plug", "plug-kitchen", "iot", "TP-Link Tapo", 150, "Embedded", "n_base", "asus", "wifi", ((80, "http", ""),), "flaky", "Smart home", custom="Kitchen smart plug", band="2.4 GHz"),
    S("p1", "p1-meter", "iot", "HomeWizard", 151, "Embedded", "n_guest", "asus", "wifi", ((80, "http", ""),), "normal", "Smart home", custom="Energy meter", band="2.4 GHz"),
    S("printer", "printer-office", "printer", "Brother Industries", 130, "Embedded", "sw_office", "snmp", "wired", ((80, "http", "Brother"), (631, "ipp", "CUPS"), (9100, "jetdirect", "")), "normal", "Family", custom="Office printer"),
]

GROUPS = [("Network", "#2563eb"), ("Servers", "#7c3aed"), ("Cameras", "#dc2626"), ("Family", "#16a34a"), ("Media", "#d97706"), ("Smart home", "#0891b2")]
BY_KEY = {d.key: d for d in DEVICES}


def ip(spec: Spec) -> str:
    return f"{SUBNET}.{spec.octet}"


def mac(spec: Spec) -> str:
    return f"{OUI.get(spec.vendor, 'a0:b1:c2')}:{spec.octet // 256:02x}:{(spec.octet * 7) % 256:02x}:{(spec.octet * 13 + 5) % 256:02x}"


def chain(key: str) -> list[str]:
    """The device and everything it hangs on, up to the router."""
    out = []
    while key:
        out.append(key)
        key = BY_KEY[key].parent
    return out


# The devices the demo owner marked "always on" (they should be online all the time): the network gear, the servers and guests that run the house, and the
# outdoor cameras. mesh-garage and sw-garden are flaky on purpose, so the always-on view has something to show. Nothing else is marked: a few
# well-behaved devices are left for the "suggested" list of the chooser.
ALWAYS_ON = frozenset({"gw", "n_base", "n_attic", "n_guest", "n_garage", "sw_rack", "sw_office", "sw_garden", "pve", "nas", "rpi_docker", "rpi_dns", "hv", "ha",
                       "docker1", "web1", "proxy", "dns1", "cam_front", "cam_drive"})
