"""Demo stand-in: the real plugin is not installed here, so nothing in the demo ever talks to a host."""


def run(config, context=None):
    raise RuntimeError("This is a demo: plugins do not run here.")
