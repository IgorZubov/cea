#!/usr/bin/env python3
"""Import every top-level module of the distributions installed in the CEA venv,
then linger so import-time threads/timers get a chance to show themselves.

Usage: python py_import.py <wait-seconds>
"""
import importlib
import importlib.metadata as md
import os
import sys
import time

VENV = "/sandbox/venv"


def top_levels(dist):
    names = set()
    try:
        tl = dist.read_text("top_level.txt")
        if tl:
            names.update(x.strip() for x in tl.splitlines() if x.strip())
    except Exception:
        pass
    for f in dist.files or []:
        parts = f.parts
        if not parts or parts[0].endswith((".dist-info", ".egg-info", ".data")) or parts[0] in ("..", "__pycache__", "bin"):
            continue
        if len(parts) == 1 and parts[0].endswith(".py"):
            names.add(parts[0][:-3])
        elif len(parts) > 1 and parts[1] == "__init__.py":
            names.add(parts[0])
    return {n for n in names if n.isidentifier()}


def main():
    wait = float(sys.argv[1]) if len(sys.argv) > 1 else 5
    mods = set()
    for dist in md.distributions():
        loc = str(getattr(dist, "_path", ""))
        if loc.startswith(VENV) and dist.metadata["Name"] not in ("pip", "setuptools", "wheel"):
            mods |= top_levels(dist)
    sys.path.insert(0, os.getcwd())
    for m in sorted(mods):
        try:
            importlib.import_module(m)
            print(f"[cea] imported {m}")
        except BaseException as e:  # SystemExit from hostile modules included
            print(f"[cea] import {m} failed: {type(e).__name__}: {e}")
    if not mods:
        print("[cea] no importable modules found")
    time.sleep(wait)


if __name__ == "__main__":
    main()
