"""Shared helpers for the plugin tests: an in-process runner and a tiny way to build plugin folders."""

import json
from types import SimpleNamespace

from app.plugins.runner import PluginRunError


def make_runner(**fakes):
    """runner(plugin, action, config) that calls fakes[plugin.id].<action>(config) in this process.

    A fake is any object (or SimpleNamespace) with test/fetch functions. Exceptions become PluginRunError the same
    way the real worker reports them.
    """
    calls = []

    def runner(plugin, action, config, timeout=None, payload=None):
        calls.append((plugin.id, action, dict(config)))
        fake = fakes[plugin.id]
        try:
            return getattr(fake, action)(config) if payload is None else getattr(fake, action)(config, payload)
        except PluginRunError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise PluginRunError(str(exc) or exc.__class__.__name__, bool(getattr(exc, "auth_failed", False))) from exc

    runner.calls = calls
    return runner


def fake(fetch=None, test=None):
    return SimpleNamespace(fetch=fetch or (lambda cfg: {}), test=test or (lambda cfg: {"message": "ok"}))


def write_plugin(root, plugin_id="demo", kind="topology", py=None, manifest=None):
    """Create <root>/plugins/<plugin_id>/ with a valid manifest and a plugin.py; returns its path."""
    folder = root / "plugins" / plugin_id
    folder.mkdir(parents=True)
    data = {
        "id": plugin_id, "name": plugin_id.title(), "version": "1.0.0", "api_version": 1, "kind": kind, "timeout": 10,
        "config": [{"key": "host", "type": "text", "label": "Host", "required": True}, {"key": "secret", "type": "password", "label": "Secret"}],
    }
    data.update(manifest or {})
    (folder / "plugin.json").write_text(json.dumps(data))
    (folder / "plugin.py").write_text(py or "def test(config):\n    return {'message': 'hi ' + config['host']}\n\ndef fetch(config):\n    return {'nodes': [], 'clients': []}\n")
    return folder
