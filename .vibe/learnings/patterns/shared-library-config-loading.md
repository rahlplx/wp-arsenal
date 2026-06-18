# Pattern: Config Loading in Shared Library Constructor

## Problem
When 20 scripts share a base library (`WPConnection`), 18 of them bypassed config loading
because they used `WPConnection(args)` directly. Only 2 scripts called `connect_from_args()`
which did the loading. The `--config` flag was documented as the primary usage pattern
but silently ignored by 90% of scripts.

## Solution
Move config loading into `WPConnection.__init__()` — the one place every consumer
must pass through — instead of a utility function that callers can bypass:

```python
def __init__(self, args: argparse.Namespace):
    try:
        import config_loader
        args = config_loader.load_config(args)
    except ImportError:
        pass
    self.host = args.host
    # ...
```

This guarantees every script gets config loading regardless of how they construct
the connection object.

## When to Use
Any time a shared library constructor has "setup" logic that all consumers must run.
Put it in `__init__`, not in a helper function that callers can forget to call.

## Tested On
wp-arsenal, 2026-06-18 — Fixed M7 from vibe-review (18/20 scripts silently ignoring --config)
