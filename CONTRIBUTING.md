# Contributing to Netlens

Thank you for wanting to help. Bug reports, ideas, documentation fixes, plugins and code are all welcome. By taking part you agree to
follow the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions are licensed under the project's [PolyForm Noncommercial license](LICENSE). By sending a contribution you also allow the
maintainer to license it under other terms, including commercial ones (this is how Netlens offers commercial licenses), and you confirm that you
wrote it or may share it.

## Ways to help

* **Report a bug or ask a question**: open an [issue](https://github.com/Gatlarf/netlens/issues/new/choose) and pick a template.
  The version (Settings → About) and your install method make a report much easier to act on. Leave passwords, tokens and
  the addresses of other people out of logs and screenshots.
* **Suggest a feature**: describe the problem you have first, then the change you would like. Small, focused ideas move fastest.
* **Security problems**: do **not** open an issue; follow the [security policy](SECURITY.md).
* **Write a plugin** for a router, switch, hypervisor, DNS server or reverse proxy: the contract is in
  [`app/plugins/PLUGINS.md`](app/plugins/PLUGINS.md) and the submission steps are in [`plugin-index/README.md`](plugin-index/README.md).
  A plugin lives in its own repository or release; you add one small JSON file to the index.
* **Improve the documentation**: the README is the manual. Fixes to wording, steps that did not work for you, and missing
  explanations are very welcome.

## Before you start a larger change

Open an issue (or comment on an existing one) so we can agree on the direction first. That avoids work on something that does not
fit, for example a feature that needs a new dependency or changes what Netlens stores.

## Development setup

You need Python 3.12 and, for scan tests, nothing else (no real network or nmap is needed).

```bash
git clone https://github.com/Gatlarf/netlens.git && cd netlens
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest                                  # the whole suite, about two minutes
NETLENS_DATA_DIR=./data NETLENS_TOKEN=dev python -m app.main     # http://localhost:8080
```

To run the image you built from your changes, use the build override:
`docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`.

## How the code is organised

* `app/` is a FastAPI application with SQLite (`app/db.py` holds the schema and its migrations) and plain JavaScript modules in
  `app/static/js` **without a build step**: no bundler, no npm packages. Please keep it that way.
* `app/plugins/` is the plugin host. Plugins (`plugins/` in this repository, or installed from the index) use the **Python standard
  library only** and run in a separate process.
* `tests/` has the tests. A static test checks the browser modules too.
* `plugin-index/` is the public plugin index and the scripts that validate it.

## Making a change

1. Fork, then create a branch from `main`.
2. Keep the change focused: one fix or one feature per pull request. Match the style of the code around it (naming, comments,
   idiom); do not reformat unrelated code.
3. **Add or update tests** for new behaviour and for every fix. Run `python -m pytest` before you push.
4. **Add a line to [`CHANGELOG.md`](CHANGELOG.md)** for anything a user can see. Follow the existing format: a bullet
   `- **Title**: what changed` under `### Added`, `### Changed` or `### Fixed` of the newest release heading; put a `★` before
   `**Title**` only for notable changes (those fill the "What's new" popup).
5. Update the README when behaviour, settings or setup steps change.
6. Never commit secrets, real tokens, passwords or network details of your own. Test data should use documentation addresses
   (`192.0.2.0/24`, `198.51.100.0/24`) or the private ranges used in the existing tests.
7. Open the pull request and fill in the template. Every push runs the tests on GitHub; they must pass.

The version number is generated (`<major.minor from VERSION>.<commits since VERSION last changed>`, see `contrib/version.sh`), so do not edit `VERSION` in a normal change.

## Commit messages

Short summary in the imperative mood on the first line (`Fix the login throttle behind a proxy`), then a blank line and the
reason if it is not obvious. Explain *why*, the diff already shows *what*.

## Plugins and the review levels

A plugin in the index is **Community** (only automatic checks passed), **Reviewed** (a trusted reviewer read this exact version)
or **Verified** (read *and* tested on real hardware). Authors cannot give themselves a level. If you can test a plugin on hardware you own,
a test report on its issue is a real contribution: say which model and firmware you used and what worked.

## Questions

If something here is unclear, open an issue with the question template. Improving this document is a fine first contribution.
