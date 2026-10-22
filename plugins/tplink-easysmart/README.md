# TP-Link Easy Smart switch (topology plugin)

Monitors TP-Link **Easy Smart** switches (TL-SG105E, TL-SG108E, TL-SG1016PE, TL-SG1024DE and relatives). They are cheap "unmanaged plus" switches: no SNMP, no CLI, only a web page.

## What you get

* The switch as a node in the hierarchy and on the map (model, MAC address, IP address).
* A **Switch ports** card on the switch's device page: link state and speed (10/100/1000, half/full), packets per second sent and received, bad packets in the last 24 hours, link changes.
* The switch does not tell which device is on which port. Say so yourself: on the switch's page, the **Connected devices** card (or a device's *Network position*) connects a device to a port, and Netlens remembers it.
* An event (`link_down` / `link_up`) when a port loses or gets its link between two syncs, so you can be notified about it.

## What you do not get

These switches have **no MAC address table** in the web interface, so Netlens cannot tell which device sits behind which port. Counters are packets (good and bad), not bytes. PoE data of the TL-SG1016PE is not read yet.

## How it works

Per sync it logs in (`POST /logon.cgi`), reads `SystemInfoRpm.htm` and `PortStatisticsRpm.htm`, and logs out (`GET /Logout.htm`). Nothing is changed on the switch. A refused login stops the automatic syncing until you save the settings or press **Sync now**, so a wrong password cannot lock the switch.

## Security note

These switches use plain HTTP and, after a login, trust every request from the same IP address (CVE-2017-17746). Netlens logs out after each read. Run it from a machine you trust and keep the switch on a trusted network. The password is at most 16 characters.

## Credits

The page format was learned from [check_tplink](https://github.com/Clete2/check_tplink) (MIT) and [essstat](https://github.com/psmode/essstat) (GPL-3). No code was copied.

## Status

Tested on a real TL-SG1016PE hardware 3.0 (firmware 1.0.0 Build 20210825 Rel.52031): model, MAC, 16 ports, link speeds and counters read correctly. Other models and firmware follow the same page format but are untested. Simulated-switch tests are in `tests/test_plugin_tplink_easysmart.py`. Run **Run diagnostic** on the plugin page when something does not look right and send the report.
