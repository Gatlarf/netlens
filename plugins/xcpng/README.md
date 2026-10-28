# Netlens plugin: XCP-ng / XenServer / Xen Orchestra

A `hypervisor` plugin for **Vates VMS** (XCP-ng managed by Xen Orchestra) and for **XenServer**. It shows which virtual machine runs on which host, with their MAC and IP addresses, and the storage repositories of each pool. Read-only, unless you let auto-remediation restart a VM.

## Two ways in, chosen by itself

| Address you enter | What Netlens talks to | Notes |
|---|---|---|
| a **Xen Orchestra** (XO) | the REST API under `/rest/v0` | One line is enough: XO shows every pool it manages. A **read-only user is enough** (see below). |
| the **pool master** of an XCP-ng or XenServer pool | the XAPI over JSON-RPC (`/jsonrpc`) | For people without XO. One line per pool, always the master. |

Netlens asks `/rest/v0/ping` first: an XO answers, a plain host does not.

## Set-up with Xen Orchestra (recommended)

1. In XO make a user for Netlens (Settings → Users, permission *None*) and give it the built-in role **Read only** (Settings → ACLs / Roles: copy the template *Read only*, attach the user to the copy). That role reads the pools, hosts, VMs, disks, networks and the backup information, and XO refuses every action for that user. (Tested.)
2. In Netlens open the plugin, enter the address of XO (`https://xo.example.com`), the user name and password, or an XO authentication token (`xo-cli create-token`) in the token column. **Test**, enable.
3. For a self-signed certificate, fill in its **SHA-256 fingerprint**: Netlens then trusts exactly that certificate and sends nothing to another one. Turning off *Verify TLS certificate* is the weaker alternative.

## Set-up without Xen Orchestra

Enter the address of the **pool master** and a login for it. XCP-ng and XenServer know local users only for `root`; other users need Active Directory (then give the account the *Read Only* role). Mind that a root login can do everything on the pool: use Xen Orchestra with a read-only user if you can, and give the pool master a fingerprint.

## What it reads

- **Hosts**: name, management address and MAC, whether the host is up.
- **Virtual machines** (templates, snapshots and the control domain are left out): state (`running`, `stopped`, `paused`), the host, the MAC addresses of the NICs, the IPv4 addresses the **Xen guest tools** report (a VM without tools has no address), the processors, memory, disk size, tags, start time, and the operating system the tools report.
- A VM that is not running has no host in Xen. In a pool with **one** host it is shown under that host; in a bigger pool it has no host until it runs.
- **Storage**: every repository with size and use, as a storage system per pool (Storage page).

## Restarting a VM (auto-remediation)

Netlens can reset (hard reboot), reboot, shut down or start a VM when a remediation rule says so. That needs more than the read-only role: give the Netlens user the role **VM operator** (XO), or use a login that may operate VMs. *Reboot* and *shutdown* ask the guest through the Xen tools; a VM without tools answers that it cannot, and *reset* is the hard way.

## Security

The address must be `https://`: a login over plain `http://` would cross the network unencrypted, so it is refused unless you switch on *Allow plain http* (for a lab). A certificate fingerprint pins exactly one certificate. Netlens only reads; nothing is written to the Xen side except the power actions you allow.

## What was tested

- **XCP-ng 8.3** (ISO 20260806, nested in QEMU/KVM) and **Xen Orchestra 6** (REST API 0.41, from the community Docker image): both ways in, a read-only user, a wrong password, a pinned certificate (right and wrong fingerprint), the power actions, the diagnostic. Two VMs without an operating system, so no guest-tools addresses: those follow the Xen documentation and are covered by a test with simulated agent data.
- **Not tested**: XenServer itself (the XAPI is the same), pools with several hosts, shared and XOSTOR repositories, Active Directory logins.

The answers the tests replay were recorded from that lab (`tests/fixtures/xen`).
