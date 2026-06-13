'use strict';

const assert = require('assert');
const {
  buildProvisionCommand,
  buildProvisionCommands,
  buildSetMpcPasswordSshCommand,
  normalizeEthAddress,
} = require('./provision-command.js');

const sample = '0xabcdef0123456789abcdef0123456789abcdef01';
const ip = '203.0.113.50';

assert.strictEqual(
  normalizeEthAddress('0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'),
  sample,
);

const onVps = buildProvisionCommand({
  ref: 'main',
  nodeMgtKey: sample,
  vpsIp: ip,
  delivery: 'on-vps',
});

assert(onVps.includes('raw.githubusercontent.com/ContinuumDAO/mpc-config/main/'));
assert(onVps.includes('--node-mgt-key'));
assert(onVps.includes(sample));
assert(onVps.includes('--ip'));
assert(onVps.includes(ip));
assert(onVps.includes('--install-systemd'));
assert(onVps.includes('| bash -s --'));

const viaSsh = buildProvisionCommand({
  nodeMgtKey: sample,
  vpsIp: ip,
  delivery: 'via-ssh',
});

assert(viaSsh.includes(`ssh -o StrictHostKeyChecking=accept-new root@${ip}`));

const both = buildProvisionCommands({ nodeMgtKey: sample, vpsIp: ip });
assert.strictEqual(typeof both.onVps, 'string');
assert.strictEqual(typeof both.viaSsh, 'string');

assert.throws(() => buildProvisionCommand({ vpsIp: ip }), /nodeMgtKey|publicMgtKey/);
assert.throws(() => normalizeEthAddress('0x1234567890abcdef1234567890abcdef12345678'), /placeholder/);

assert.strictEqual(
  buildSetMpcPasswordSshCommand({ vpsIp: ip }),
  "ssh root@203.0.113.50 'passwd mpcnode'",
);

console.log('provision-command.test.js: ok');
