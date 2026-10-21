# Netlens plugin: SNMP switches

Asks your **managed switches** over SNMP which device is plugged into which port, and how the switches are connected to each other. Netlens then
shows **"Connected to: SW_GARDEN · port gi1/0/5"** on every device's page and puts the switches and the devices behind them in the right place in
the hierarchy and on the map. It works with any switch that offers SNMP v1, v2c or v3 and the standard bridge MIB: TP-Link (JetStream / Smart),
Netgear, HP / Aruba, Cisco, Zyxel, MikroTik, Ubiquiti and others. Read-only: it only ever sends SNMP *get* requests.

> **Status: verified against a real device** (reported by the maintainer, 2026-10-16), after tests against simulated switches (a codec checked against a real SNMP packet, and a simulated network of two switches with LLDP). The Cisco parts of 1.2.0 (per-VLAN tables, CDP) follow Cisco's documentation and are tested against a simulated Catalyst only; a report from a real Catalyst is welcome. More switch models are still welcome: *Run diagnostic* makes a report.
> Please try it on a real switch and report what you see, see *Testing* below.

## What it reads

| MIB | Objects | Used for |
|---|---|---|
| SNMPv2-MIB | `sysDescr`, `sysName` | what the switch is called |
| BRIDGE-MIB | `dot1dBaseBridgeAddress`, `dot1dBasePortIfIndex` | the switch's own MAC, bridge port to interface |
| IF-MIB | `ifName` (else `ifDescr`), `ifPhysAddress` | port names, and the MACs the switch itself uses |
| Q-BRIDGE-MIB (else BRIDGE-MIB) | `dot1qTpFdbPort` / `dot1dTpFdbPort` and their status | the MAC address table: which MAC was learned on which port |
| LLDP-MIB | `lldpRemChassisId`, `lldpRemSysName`, `lldpLocPortId` | which port leads to which other switch |
| CISCO-CDP-MIB | `cdpCacheDeviceId`, `cdpCacheDevicePort`, `cdpCacheAddress` | the same for Cisco neighbours that only speak CDP (matched to your switches by management address, else by name) |
| CISCO-VTP-MIB | `vtpVlanState` | which VLANs a Cisco switch has (see below) |

How Netlens uses it: every switch you list becomes a node. Two switches that see each other by LLDP are linked (from the **core switch**, which you can
name, else the one with the most neighbours). Every MAC in an address table becomes a wired client **of the switch whose port it was learned on,
unless that port is an uplink to another switch**: a TV plugged into the garden switch is also visible in the core switch's table, but there it sits
on the port that leads to the garden switch, so it is ignored. Without LLDP, a MAC seen on several switches is attributed to the one where its port
carries the fewest addresses (the edge). Multicast and the switches' own addresses are skipped.

### Cisco: one MAC table per VLAN (version 1.2.0)

A Cisco IOS switch keeps a separate BRIDGE-MIB for every VLAN and shows only VLAN 1 to a plain community string. When the switch is a Cisco (its `sysObjectID` is below 1.3.6.1.4.1.9) and has no Q-BRIDGE table, Netlens asks for each operational VLAN with `community@vlan` (`public@25`) and merges the tables. VLANs the switch does not answer for are skipped, and three silent VLANs in a row stop the loop. The setting *Cisco VLAN indexing* can force it (*Always*, for a Cisco that has a Q-BRIDGE table that is incomplete) or turn it off. Juniper, Huawei, HP/Aruba and most others publish the whole table through Q-BRIDGE-MIB and need none of this.

## Set-up

1. On each switch switch SNMP on (v2c) and set a **read** community (not `private`, and not a write community). Many switches have it under
   *System → SNMP*. TP-Link Omada / JetStream smart switches: *System → SNMP → Global Config*, then *Community Config* with *Read Only*.
   Also switch **LLDP** on if the switch has it (it is how Netlens learns that two switches are connected).
2. In Netlens: *Settings → Integrations → Plugin store → SNMP switches → Install* (community plugins ask for an extra confirmation), then open its
   page, enter the switches' addresses (`192.168.1.2, 192.168.1.3`), the community and, if you like, the core switch.
3. **Test connection**, **Save**, **Turn on**, **Sync now**. Netlens asks again after every scan.

SNMP v1 and v2c are not encrypted: the community string travels in clear text on your network, so use a read-only community and keep SNMP off the internet.

### SNMPv3 (version 1.3.0)

Choose *v3* as the SNMP version and fill in the *SNMPv3* section: a user name, an authentication protocol and password (SHA, SHA-224/256/384/512 or MD5) and an encryption protocol and password (AES-128 or DES). Passwords are at least 8 characters. On a Cisco switch, for example: `snmp-server group NETLENS v3 priv read ALL`, `snmp-server user netlens NETLENS v3 auth sha <password> priv aes 128 <password>`. The same user is used for every switch in the list. It also reads Cisco per-VLAN tables (through the context `vlan-<n>`). AES-192/256 is not supported. A refused user stops the automatic syncing (like any refused login) until you save the settings or press *Sync now*. The encryption is written in plain Python inside the plugin (plugins cannot install packages) and was checked against the FIPS test vectors and a reference implementation, and the whole client against a real net-snmp 5.9.3 agent with SHA/AES, MD5/DES, SHA-256/AES, SHA-512 without encryption and no authentication.

## Testing (what we would like to know)

- [ ] *Test connection* finds all your switches and a plausible number of learned MAC addresses.
- [ ] A device that is plugged into a switch shows **Connected to: <switch> · port <name>** on its page, and the port name is the one printed on the switch.
- [ ] Switches that are cabled together appear below each other in the hierarchy (needs LLDP on both).
- [ ] A device is not attributed to the wrong switch (for example the core one).
- [ ] After moving a cable to another port, the new port shows after the next scan.

Press **Run diagnostic** on the plugin's page and send the report: it lists, per switch, which tables answered and how many rows they have (no names,
addresses or MACs). If *Test connection* only times out: check the address, the community string, and that no firewall blocks UDP port 161.

## Limits

- Devices behind an unmanaged switch or an access point are shown on the port that leads to it (Netlens cannot see further).
- A switch without LLDP gives no links between switches; set the parent of the switches by hand (device page → Edit → Network position).
- Very large networks: a table longer than 40,000 rows is cut off.
