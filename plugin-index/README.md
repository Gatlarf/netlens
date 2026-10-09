# Netlens plugin index

The plugin index is the public list of plugins that Netlens shows under **Settings → Integrations → Browse plugins**.
It only **points at** plugins: the code stays in the author's own repository or release. Netlens downloads a plugin only
when a user presses *Install*, checks the file against the SHA-256 pinned here, and then applies the same safety checks as
a manual upload. Installed plugins start switched off.

```
plugin-index/
  plugins/<id>.json     one file per plugin, written by its author (this is what you submit)
  reviews/<id>.json     review records, written only by trusted reviewers
  REVIEWERS             who the trusted reviewers are
  index.json            generated from the two folders above (do not edit by hand)
  template/             a plugin to copy as a starting point
  tools/                the validator and the scripts the CI runs
```

## Review levels

| Level | Meaning | What users see |
|---|---|---|
| **Verified** | a trusted reviewer read the code of **this exact version** *and* tested it on real hardware (the device list is shown) | green badge |
| **Reviewed** | a trusted reviewer read the code of this exact version, but nobody tested it on hardware | blue badge |
| **Community** | only the automatic checks below passed | amber badge, a warning, and an extra confirmation before install |

A review names a **version and its checksum**. If a release changes, or a new version appears, it is *Community* again until
it is reviewed again. Authors cannot give themselves a level: Netlens only honours `reviews/`, and only trusted reviewers
may change that folder.

## Submitting a plugin

1. **Write it** (start from [`template/`](template/); the contract is in [`app/plugins/PLUGINS.md`](../app/plugins/PLUGINS.md)) and test it:
   ```
   python plugin-index/tools/check_plugin.py path/to/my-plugin
   python plugin-index/tools/check_plugin.py path/to/my-plugin --output sample_output.json   # recorded output
   python plugin-index/tools/check_plugin.py path/to/my-plugin --config settings.json        # your real device
   ```
2. **Release it**: a zip with `plugin.json` and `plugin.py` (and any extra `.py` files) attached to a GitHub release. The template's
   `release.yml` does this when you push a tag and prints the SHA-256. Compute it yourself with `sha256sum plugin.zip`.
3. **Add your entry** `plugin-index/plugins/<id>.json` (the file name is the plugin id) in a pull request. You can use GitHub's web editor:

   ```json
   {
     "id": "my-router",
     "name": "My router",
     "kind": "topology",
     "description": "One or two sentences.",
     "author": "Your name",
     "homepage": "https://github.com/you/netlens-plugin-my-router",
     "license": "MIT",
     "supports": ["Acme R1000", "Acme R2000 (firmware 3.x)"],
     "releases": [
       {
         "version": "1.0.0",
         "download_url": "https://github.com/you/netlens-plugin-my-router/releases/download/v1.0.0/plugin.zip",
         "sha256": "64 hex characters",
         "api_version": 1,
         "min_netlens": "0.2.45",
         "released": "2026-10-09",
         "changelog": "First release."
       }
     ]
   }
   ```
   `kind` is `hypervisor` or `topology`. `download_url` must be an `https://github.com/...` release asset. `version`, `kind` and
   `api_version` must match the `plugin.json` inside the zip.
4. **Automatic checks** run on your pull request (see below). Fix what they report.
5. **Review**: reviewers read the code of your release. They need a way to judge it, so please say in the pull request which
   device and firmware it was tested on, and ideally offer recorded sample responses. If a reviewer owns the device, they test it and
   set **Verified**; otherwise it becomes **Reviewed** or stays **Community**. Merging adds it to the index within a minute or two.

### Shipping an update

Add a new object to `releases` (never edit or remove an old one: a published version is **immutable**, the CI refuses a changed URL or
checksum). Users see "update available", nothing is installed automatically, and they can go back to the previous version.

## Automatic checks (CI)

* the entry is valid (id equals file name, GitHub release URL, 64-hex checksum, versions);
* the **download matches the pinned checksum**, passes Netlens' own upload checks (safe zip, size, manifest, syntax, `fetch`/`test`) and
  its `plugin.json` agrees with your entry;
* a **static scan** (`tools/static_scan.py`) flags risky code. *Blocking* findings fail the check: `eval`/`exec`, starting programs,
  native code, touching SQLite, `pickle`. A reviewer may allow a rule for one exact version after reading it
  (`"allow_flags": ["subprocess"]` in the review). *Notes* (file access, environment variables, URLs to other hosts, decoding data,
  listening sockets) are only reported, and reviewers look at them;
* published versions did not change;
* review records are only changed by trusted reviewers.

The scan cannot prove a plugin safe. It points reviewers at what to read.

## For reviewers

Add or edit `plugin-index/reviews/<id>.json`:

```json
{
  "id": "my-router",
  "reviews": [
    {
      "version": "1.0.0",
      "sha256": "the same checksum as the release",
      "level": "verified",
      "reviewer": "your-github-name",
      "date": "2026-10-09",
      "tested_on": ["Acme R1000, firmware 3.2"],
      "notes": "Reads two pages, no writes.",
      "allow_flags": []
    }
  ]
}
```
Read **all** the code of that version (download the zip, run `tools/static_scan.py`), check that it talks only to the configured device,
never logs or sends credentials elsewhere, handles a refused login as `auth_failed`, and returns valid data. Use `verified` only if
someone really ran it against the device. To become a reviewer, ask in a pull request that adds your GitHub name to `REVIEWERS`
(the repository owner approves).

## Running your own index

The index address is a setting in Netlens (Browse plugins → Plugin index settings). A custom index is any `https://` URL serving a
file in the same format (`"schema": 1`); it may point at downloads on any https host. `tools/build_index.py` builds one from a
folder of entries.
