# Netlens plugin: Technitium DNS

Registers your devices in **Technitium DNS Server**: an A record and a reverse (PTR) record for every device Netlens knows and DNS does not, and a
new address for a device whose IP changed (DHCP). Works with a **primary and secondary** server and with a **Technitium cluster**. Everything is shown
in a preview under *Settings → Integrations → DNS registration* and written only after you approve it (or after every scan, if you switch automatic
mode on).

> **Status: tested against a simulated Technitium server only** (the API calls follow the official API documentation). Please try it on a scratch zone
> first and report what you see.

## What it never does

- It only changes records that carry the comment **`managed by Netlens`** (or that Netlens remembers writing). A record made by anything else, for
  example a Windows machine that registered itself by dynamic update, is never changed or removed, and a name that is already used by such a record
  is shown as a **conflict** and left alone.
- It does not register Windows machines by default, waits a few hours before registering a device that has no record (so a client that registers
  itself gets there first), and registers only devices you marked as *known*.
- It never removes records unless you switch removal on **and** the account has Delete permission.

## Set-up

1. **A user with limited rights on each Technitium server** (*Administration → Users*): *View* and *Modify* on your zone (for example
   `home.example.com`) and on the reverse zones (`0.168.192.in-addr.arpa`), nothing else, and no Delete permission. Make a **token** for it
   (*Administration → Sessions → Create token*). Do not use your admin account.
2. In Netlens install **Technitium DNS** (*Settings → Integrations → Browse plugins*) and open its page: enter the address of **every** server
   (`http://192.168.0.2:5380, http://192.168.0.3:5380`) and the token for each (comma separated, in the same order; one token if it is the same for all).
   *Verify TLS certificate* only matters for https addresses.
3. Open *Settings → Integrations → DNS registration*: enter your network and zone (`192.168.0.0/24 = home.example.com`; several lines for
   several networks), save, press **Read the DNS server now** and look at the preview.
4. Approve what you want. When the preview keeps showing what you expect, you can switch on *Apply automatically after every scan*.

## Servers: primary/secondary or cluster

You list all servers. Netlens writes a zone on every server that holds it as a **Primary** zone: with a primary and a secondary that is the primary
(the secondary copies it by zone transfer), in a **cluster** it is the primary node (the other nodes get the zone from there). When you migrate to a
cluster nothing needs to change in the settings. A server that is down is reported; Netlens never writes to a secondary.

## Records

| What | Technitium call |
|---|---|
| read | `zones/list`, `zones/records/get?listZone=true`, `admin/cluster/state` |
| add | `zones/records/add` (A with `ptr=false`; the PTR record is added separately in the reverse zone), comment `managed by Netlens`, **no TTL** (zone/server default) |
| change address | `zones/records/update` with the current value and `newIpAddress`, so a record that changed meanwhile is never overwritten |
| remove (optional) | `zones/records/delete` |

Before each add the plugin asks the server whether the name has meanwhile got a record, and does not write if so.

## If something is odd

*Run diagnostic* on the plugin's page lists per server how many zones and records it saw, whether the server returns record comments (older versions
may not; Netlens then relies on what it remembers writing), and whether dynamic updates are allowed in your zone (that is how Windows registers).
