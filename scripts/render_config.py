#!/usr/bin/env python3
"""
Render wazuh/config/ossec.conf into a deployable config.

Two jobs:
  1. Substitute __PLACEHOLDER__ tokens from .env.
  2. Drop any <integration> block whose secret is still unset, so an
     unconfigured integration is absent rather than failing on every alert.

Usage:  render_config.py <template> <output> [env_file]
"""
import re
import sys
from pathlib import Path

UNSET_MARKERS = ("REPLACE_ME", "CHANGEME", "")


def load_env(path):
    values = {}
    if not path.exists():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def is_unset(value):
    return value is None or value.strip() in UNSET_MARKERS or "REPLACE_ME" in value


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: render_config.py <template> <output> [env_file]")

    template = Path(sys.argv[1])
    output = Path(sys.argv[2])
    env_file = Path(sys.argv[3]) if len(sys.argv) > 3 else template.parent.parent.parent / ".env"

    env = load_env(env_file)
    config = template.read_text()

    # 1. Substitute every placeholder we have a value for.
    resolved, unresolved = [], []
    for token in sorted(set(re.findall(r"__([A-Z0-9_]+)__", config))):
        value = env.get(token)
        if is_unset(value):
            unresolved.append(token)
        else:
            config = config.replace("__{}__".format(token), value)
            resolved.append(token)

    # 2. Remove integration blocks that still carry an unresolved placeholder.
    dropped = []

    def strip_unconfigured(match):
        block = match.group(0)
        if "__" in block and re.search(r"__[A-Z0-9_]+__", block):
            name = re.search(r"<name>([^<]+)</name>", block)
            dropped.append(name.group(1) if name else "unnamed")
            return ""
        return block

    config = re.sub(r"[ \t]*<integration>.*?</integration>\n?", strip_unconfigured,
                    config, flags=re.DOTALL)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(config)

    print("rendered -> {}".format(output))
    print("  substituted : {}".format(", ".join(resolved) or "none"))
    print("  unresolved  : {}".format(", ".join(unresolved) or "none"))
    print("  integrations disabled (no secret yet): {}".format(", ".join(dropped) or "none"))

    leftover = sorted(set(re.findall(r"__([A-Z0-9_]+)__", config)))
    if leftover:
        print("  WARNING: unresolved placeholders remain: {}".format(", ".join(leftover)))
        # A missing cluster key leaves the manager unable to start, so this one
        # is fatal rather than a warning.
        if "CLUSTER_KEY" in leftover:
            sys.exit("CLUSTER_KEY must be set in .env - generate one with: "
                     "openssl rand -hex 16")


if __name__ == "__main__":
    main()
