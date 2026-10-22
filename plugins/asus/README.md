# Netlens plugin: ASUS router (AiMesh)

A `topology` plugin. Until Netlens 0.4.43 it was built in; since then it is installed from the **Plugin store**. If you used it before, Netlens installs it again by itself after the upgrade, with your settings, and keeps it switched on.

Shows which device is connected to which AiMesh node, with Wi-Fi signal and roaming. Stock ASUSWRT, read-only, no SSH (it signs in to the router's web interface the way a browser does). Tested on an ASUS RT-AX92U.

## Set-up

Enter the address of the router's web interface (`https://192.168.50.1:8443` or `http://router.asus.com`), a user name and password (a separate admin user is best), **Test**, enable.

## Traffic Analyzer (applications and devices)

Since 1.2.0 the plugin also reads the router's **Traffic Analyzer** when it is on (router: *Adaptive QoS > Traffic Analyzer > Statistic*, switch it on; the first figures appear after about an hour). Per day it takes the traffic of every application (the router's own application recognition) and of every device, up and down, and Netlens shows them in **Statistics > Network > Applications**: the top applications, the top devices and the traffic per day. Only today and yesterday are read on each sync, and the day ends at the router's own midnight (its clock is read from the router). The figures are the router's: Netlens does not measure anything itself.

Models without Trend Micro's traffic analysis do not have these pages; the plugin then just skips this part. Untick *Read the Traffic Analyzer statistics* to turn it off. **Run diagnostic** reports whether the pages answered and the shape of one row (never names or addresses).
