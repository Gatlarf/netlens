# Security policy

Netlens scans networks, stores credentials for the services it connects to and can open a terminal, so security reports are taken
seriously. Thank you for taking the time to report one responsibly.

## Supported versions

Only the **newest published release** (`ghcr.io/gatlarf/netlens:latest`) receives security fixes. Netlens does not update itself:
pull the newest image to get a fix (see [Updating](README.md#updating-to-a-new-version)). Plugins are separate: a fix for a plugin
is a new plugin release under **Settings → Plugin store**.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately:

1. Go to the **Security** tab of this repository and press **Report a vulnerability**
   (<https://github.com/Gatlarf/netlens/security/advisories/new>). Only the maintainers can see it.
2. Describe what you found, the version (Settings → About), how to reproduce it, and what an attacker gains.
   A short proof of concept helps. Please do not include real passwords, tokens or the data of other people.

You can expect an acknowledgement within about **7 days** and a first assessment within about **14 days**. This is a
volunteer-run project, so these are intentions and not guarantees. We will keep you informed, agree on a disclosure date with you
(usually when a fixed release is out), and credit you in the release notes if you want that.

## What is in scope

* The Netlens application and its API (login, sessions, tokens, share links, restore, the web terminal, the plugin installer).
* The container image and the compose files in this repository.
* The plugin index and the checks around it (a way to get unreviewed code installed as "verified", for example).
* The plugins in this repository (`plugins/`).

## What is not in scope

* Findings that need access an attacker should not have: an administrator, a stolen backup file or access to the Docker host.
  (Backups contain saved credentials and plugin code by design; treat them like passwords.)
* Plugins written by third parties: report those to their author. A malicious plugin in the index can be reported here.
* Missing hardening that depends on how you deploy it: Netlens speaks plain HTTP and expects a reverse proxy for HTTPS;
  see [HTTPS](README.md#https) and the `NETLENS_TRUSTED_PROXIES` setting.
* Denial of service by a user who is already logged in, and results of automated scanners without a demonstrated impact.

## Good practice for operators

* Put Netlens behind an HTTPS reverse proxy and set `NETLENS_TRUSTED_PROXIES` so the login throttle counts real visitors.
* Do not expose it to the internet without strong, unique passwords; consider a VPN or an access list in front of it.
* Keep the web terminal off or local (`NETLENS_TERMINAL`, `NETLENS_TERMINAL_REMOTE`) unless you need it.
* Install plugins only from sources you trust: a plugin is code that runs inside Netlens.
* Update regularly and read the changelog.
