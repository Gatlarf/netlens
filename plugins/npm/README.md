# Nginx Proxy Manager plugin

Shows what your Nginx Proxy Manager (NPM) publishes in Netlens (kind `proxy`, needs Netlens 0.3.116 or newer). Read-only: it logs in
(`POST /api/tokens`) and then only sends `GET` requests (`/api/`, `/api/users/me`, `/api/nginx/proxy-hosts`, `redirection-hosts`,
`streams`, `dead-hosts`, `certificates`, `access-lists`). Tested against NPM 2.15.1.

## What you get

* every **proxy host, redirection, stream and 404 host** with its domains, upstream, certificate and on/off state;
* each site tied to the **device or container behind it**: a container that publishes the forwarded port on that host (address and port
  decide), a macvlan container's own address, a device with that address or name, a container or compose service name on the proxy's own
  Docker network, `localhost` / `host.docker.internal` for the proxy's own machine. Sites Netlens cannot place are shown as *not found*;
* a *Published through the proxy* card on the upstream's device page and *Sites served* on the proxy's page;
* a **certificate expiring** event 14 days (adjustable) before a certificate used by a site ends, again at 7, 3 and 1 days, and when it has expired;
* optionally one **HTTPS check per site** (Services), sent to the proxy with the site's name, so it does not depend on DNS;
* optionally **DNS names** for the domains (Settings → DNS registration), as CNAMEs to the proxy's host, previewed and approved like
  every other DNS change.

## The user Netlens needs

In NPM open **Users → Add User** and create a user for Netlens:

* **not an administrator** and with **two-factor authentication off** (the API login cannot answer a code);
* in the user's **Permissions** set **Item Visibility: All Items** (the default, *Only Their Own Items*, hides everything you created
  yourself) and **View Only** for Proxy Hosts, Redirection Hosts, 404 Hosts, Streams, Access Lists and Certificates.

The plugin checks the account and tells you in its settings when the visibility or the permissions are wrong. It works with any account
that can read, but a view-only user cannot change anything even if the password leaks.

## Settings

| Setting | Meaning |
| :--- | :--- |
| Address | The admin interface, port 81 by default: `http://192.168.0.184:81`. |
| E-mail address, password | Of the Netlens user. |
| Proxy's own address | Only when the address above is a name or `127.0.0.1`: the LAN address of the machine NPM runs on. |
| Verify TLS certificate | For `https://` addresses. |
| Look up the names sites forward to | `nas.home.example.com` is looked up so the site can be tied to the device with that address. |
| Check every site | One HTTPS (or HTTP) check per enabled proxy host, kept in step with the proxy's list. |
| Check every (seconds) | Default 300. |
| Warn about certificates this many days before | Default 14. |

## Notes

* A wrong password pauses the plugin until you save or sync it again, so it cannot lock the account.
* Site checks ask the proxy on port 443 (sites with a certificate) or 80, and use the name of the site for the `Host` header and the
  TLS handshake. Any answer below 500 counts as up (a login page is an answer); a 502 or 504 from NPM means the upstream is down.
* Wildcard domains (`*.example.com`) get no check and no DNS name.
* The **Run diagnostic** button reports counts and yes/no answers only (no domains, names or addresses).
