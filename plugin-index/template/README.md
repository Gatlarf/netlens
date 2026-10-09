# Netlens plugin template

1. Copy this folder, rename `id`/`name` in `plugin.json`, and replace the made-up data in `plugin.py` with calls to your device
   (standard library only). The full contract is in [`app/plugins/PLUGINS.md`](../../app/plugins/PLUGINS.md).
2. Check it before you publish (from a checkout of the Netlens repository):

   ```
   python plugin-index/tools/check_plugin.py path/to/your-plugin
   python plugin-index/tools/check_plugin.py path/to/your-plugin --output tests/sample_output.json   # validate recorded output
   python plugin-index/tools/check_plugin.py path/to/your-plugin --config my-settings.json           # call your real device
   ```
3. **Keep `diagnose(config)`** (and `"diagnose": true` in `plugin.json`): it powers the *Run diagnostic* button, so testers can send you a report of what their device answered. Replace the example with your device's real answers, shapes only (see `diagnose(config)` in `PLUGINS.md`).
4. Publish: push a tag like `v1.0.0`. The workflow in `.github/workflows/release.yml` builds `plugin.zip`, attaches it to a GitHub
   release and prints the SHA-256 you need for the index entry.
5. Submit it: see [`plugin-index/README.md`](../README.md).
