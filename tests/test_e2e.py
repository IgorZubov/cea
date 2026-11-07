"""End-to-end: runs the real sandbox on the fixtures. Needs Docker/Podman.
Skipped unless CEA_E2E=1.   CEA_E2E=1 python3 -m unittest tests.test_e2e"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")


@unittest.skipUnless(os.environ.get("CEA_E2E") == "1", "set CEA_E2E=1 to run sandbox tests")
class E2E(unittest.TestCase):
    def check(self, target):
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "cea"), "check", target, "--json",
                                "--out", out, "--wait", "2"], capture_output=True, text=True, timeout=900)
            self.assertTrue(r.stdout, r.stderr)
            res = json.loads(r.stdout)
            data = json.load(open(res["report_json"]))
            return res, data

    def test_benign(self):
        res, _ = self.check(os.path.join(FIX, "benign-npm"))
        self.assertEqual(res["verdict"], "LIKELY_SAFE", res)

    def test_evil_npm(self):
        res, data = self.check(os.path.join(FIX, "evil-npm"))
        self.assertEqual(res["verdict"], "MALICIOUS")
        leaked = {l["secret"] for l in data["behaviour"]["leaks"]}
        self.assertIn("NPM_TOKEN", leaked)          # DNS + HTTPS exfil
        self.assertIn("AWS_SECRET_ACCESS_KEY", leaked)
        self.assertTrue(any(f["rule"] == "persistence" for f in data["findings"]))

    def test_evil_py(self):
        res, data = self.check(os.path.join(FIX, "evil-py"))
        self.assertEqual(res["verdict"], "MALICIOUS")

    def test_evil_script(self):
        res, data = self.check(os.path.join(FIX, "evil-install.sh"))
        self.assertEqual(res["verdict"], "MALICIOUS")
        self.assertIn("SSH_PRIVATE_KEY_FILE", {l["secret"] for l in data["behaviour"]["leaks"]})


if __name__ == "__main__":
    unittest.main()
