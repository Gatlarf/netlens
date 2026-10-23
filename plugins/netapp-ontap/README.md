# Netlens plugin: NetApp ONTAP

Shows a **NetApp ONTAP** cluster (AFF, FAS, ASA, ONTAP Select, Cloud Volumes ONTAP) on the **Storage** page and on the device pages:

- the cluster's **health** and its **nodes**, matched to the devices Netlens found (by management address and the MAC of the e0M port);
- every **aggregate** with its fill level (events at 85 and 95 percent) and state;
- **volumes and LUNs** per SVM, with the **hosts that mount a volume over NFS** linked to their devices, so a device page tells which volumes it depends on and a volume tells who uses it;
- **disks** (broken disks raise an event), failed fans and power supplies, and the emergency, alert and error events of the last day.

Events (*Storage problem*, *Storage recovered*, *Disk filling up*) go through the usual notification channels. The root volumes (`vol0`, `*_root`) and data-protection destinations are left out.

## Set-up

1. On the cluster create a read-only user: `security login create -user-or-group-name netlens -application http -authentication-method password -role readonly`.
2. In Netlens: *Settings → Integrations → Plugin store → NetApp ONTAP → Install*, open its page, enter the cluster management address (`https://192.168.0.80`), the user name and password (**+ Add server** for another cluster), **Test connection**, **Save**, **Turn on**, **Sync now**.

A refused login stops automatic syncing until you save the settings or press *Sync now* again.

## If something does not work

Press **Run diagnostic**: it shows which REST calls worked and the **names and types of the fields**, not their content (names, serial numbers, addresses and MAC addresses are removed). Send it to whoever maintains the plugin. A part an ONTAP version does not offer (for example the NFS client list before 9.8) is skipped and named in the test message.

## What was tested

**Not tested on a real cluster.** The plugin was written from NetApp's published REST API reference (ONTAP 9.8 to 9.16) and is tested against a simulator that returns the documented shapes, so it is Community level. Field names may need small corrections once a real cluster answers: please send a *Run diagnostic* report. If you can run the free ONTAP simulator or ONTAP Select evaluation, that is the best test.

## Notes for reviewers

Standard library only. The password is sent only in the `Authorization` header to the configured addresses. All requests are GET.
