# Netlens plugin: ASUS router (AiMesh)

A `topology` plugin. Until Netlens 0.4.43 it was built in; since then it is installed from the **Plugin store**. If you used it before, Netlens installs it again by itself after the upgrade, with your settings, and keeps it switched on.

Shows which device is connected to which AiMesh node, with Wi-Fi signal and roaming. Stock ASUSWRT, read-only, no SSH (it signs in to the router's web interface the way a browser does). Tested on an ASUS RT-AX92U.

## Set-up

Enter the address of the router's web interface (`https://192.168.50.1:8443` or `http://router.asus.com`), a user name and password (a separate admin user is best), **Test**, enable.

## Traffic Analyzer (applications and devices)

Since 1.2.0 the plugin also reads the router's **Traffic Analyzer** when it is on (router: *Adaptive QoS > Traffic Analyzer > Statistic*, switch it on; the first figures appear after about an hour). Per day it takes the traffic of every application (the router's own application recognition) and of every device, up and down, and Netlens shows them in **Statistics > Network > Applications**: the top applications, the top devices and the traffic per day. **Per device** (1.3.0): for the 25 busiest devices of today it also asks the router which applications that device used, shown on the device's **Network** tab (one extra request per device, within 40 seconds). Only today and yesterday are read on each sync, and the day ends at the router's own midnight (its clock is read from the router). The figures are the router's: Netlens does not measure anything itself.

Models without Trend Micro's traffic analysis do not have these pages; the plugin then just skips this part. Untick *Read the Traffic Analyzer statistics* to turn it off. **Netlens' own switch also has to be on: Settings > Traffic statistics** (off by default, because in some countries this kind of data may not be collected; switching it off deletes what was stored, and while it is off the plugin does not even ask the router). **Run diagnostic** reports whether the pages answered and the shape of one row (never names or addresses).


## The speed of the router's interfaces (1.4.0)

Every sync also reads the router's interface counters (`appGet.cgi?hook=netdev(appobj)`: what each interface has sent and received since the router started) and reports them as the ports of the main router: **WAN** (the internet connection), **LAN** (the wired ports together) and the **Wi-Fi radios**. Netlens turns the counters of two syncs into speeds (bits per second), so the router gets graphs like a switch does, and the WAN port is the line for the internet connection in the traffic graph of the HUD page (Settings > Interface can pick another interface). A sync follows the scans, so the speeds are averages over the time between two syncs. Nothing has to be switched on in the router. Untick *Record the speed of the router's interfaces* to turn it off.
