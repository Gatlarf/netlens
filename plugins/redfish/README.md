# Netlens plugin: Redfish (server BMC)

Shows **servers and storage systems** through their management controller (BMC), using the open **DMTF Redfish** standard. It works with Dell iDRAC, HPE iLO, Lenovo XClarity, Supermicro, Cisco CIMC and any other device that serves `/redfish/v1/`. Redfish is a plain HTTPS + JSON API; it has nothing to do with Red Hat and needs nothing installed on the server.

On the **Storage** page and on the device pages you get:

- the server's **health** (the worst of system, chassis, power supplies, fans, temperatures and drives), model, serial number and BIOS version;
- the **BMC** and the **network cards** as controllers, matched to the devices Netlens found by IP address or MAC, so the BMC and the server it belongs to show up together;
- **drives** (failed or degraded ones raise an event) and **RAID volumes**;
- an **alert** for every power supply, fan or sensor that is not healthy.

Events (*Storage problem*, *Storage recovered*) go through the usual notification channels.

## Set-up

1. On the BMC create a user for Netlens with the **ReadOnly** role and a long random password.
2. In Netlens: *Settings → Integrations → Plugin store → Redfish → Install*, open its page, enter the BMC's address (`https://192.168.0.70`), the user name and password (**+ Add server** for each further BMC), **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login (HTTP 401/403) stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic** on the plugin's page: it shows which calls worked and the **names and types of the fields**, not their content (names, serial numbers, addresses and MAC addresses are removed). Send it to whoever maintains the plugin. Redfish implementations differ between vendors; a part that a BMC does not offer is skipped and named in the test message.

## What was tested

Run against the **official DMTF Redfish Mockup Server** with the DMTF `public-rackmount1` mockup (a Redfish 1.22 server with system, manager, chassis, network interfaces, simple storage, power and thermal): system, BMC and network card matching, drives (healthy and degraded), a warning power supply, the diagnostic. Vendor-specific behaviour (Dell, HPE, Lenovo ...) was **not** run on real BMCs; the standard calls are the same, but please report a diagnostic from your hardware if something is missing. The newer `Storage`/`Volumes` collections are covered by a unit test only (the mockup has none).

## Notes for reviewers

Standard library only. The password is sent only in the `Authorization` header to the configured addresses. All requests are GET; at most 400 requests per sync.
