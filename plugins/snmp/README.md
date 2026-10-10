# Netlens plugin: SNMP switches

Asks your **managed switches** over SNMP which device is plugged into which port, and how the switches are connected to each other. Netlens then
shows **"Connected to: SW_GARDEN · port gi1/0/5"** on every device's page and puts the switches and the devices behind them in the right place in
the hierarchy and on the map. It works with any switch that offers SNMP v1 or v2c and the standard bridge MIB: TP-Link (JetStream / Smart),
Netgear, HP / Aruba, Cisco, Zyxel, MikroTik, Ubiquiti and others. Read-only: it only ever sends SNMP *get* requests.

> **Status: tested against simulated switches only** (a codec checked against a real SNMP packet, and a simulated network of two switches with LLDP).
> Please try it on a real switch and report what you see, see *Testing* below.

## What it reads

| MIB | Objects | Used for |
|---|---|---|
| SNMPv2-MIB | `sysDescr`, `sysName` | what the switch is called |
| BRIDGE-MIB | `dot1dBaseBridgeAddress`, `dot1dBasePortIfIndex` | the switch's own MAC, bridge port to interface |
| IF-MIB | `ifName` (else `ifDescr`), `ifPhysAddress` | port names, and the MACs the switch itself uses |
| Q-BRIDGE-MIB (else BRIDGE-MIB) | `dot1qTpFdbPort` / `dot1dTpFdbPort` and their status | the MAC address table: which MAC was learned on which port |
| LLDP-MIB | `lldpRemChassisId`, `lldpRemSysName`, `lldpLocPortId` | which port leads to which other switch |

How Netlens uses it: every switch you list becomes a node. Two switches that see each other by LLDP are linked (from the **core switch**, which you can
name, else the one with the most neighbours). Every MAC in an address table becomes a wired client **of the switch whose port it was learned on,
unless that port is an uplink to another switch**: a TV plugged into the garden switch is also visible in the core switch's table, but there it sits
on the port that leads to the garden switch, so it is ignored. Without LLDP, a MAC seen on several switches is attributed to the one where its port
carries the fewest addresses (the edge). Multicast and the switches' own addresses are skipped.

## Set-up

1. On each switch switch SNMP on (v2c) and set a **read** community (not `private`, and not a write community). Many switches have it under
   *System → SNMP*. TP-Link Omada / JetStream smart switches: *System → SNMP → Global Config*, then *Community Config* with *Read Only*.
   Also switch **LLDP** on if the switch has it (it is how Netlens learns that two switches are connected).
2. In Netlens: *Settings → Integrations → Browse plugins → SNMP switches → Install* (community plugins ask for an extra confirmation), then open its
   page, enter the switches' addresses (`192.168.1.2, 192.168.1.3`), the community and, if you like, the core switch.
3. **Test connection**, **Save**, **Turn on**, **Sync now**. Netlens asks again after every scan.

SNMP is not encrypted: the community string travels in clear text on your network, so use a read-only community and keep SNMP off the internet.
SNMPv3 is not supported yet.

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
