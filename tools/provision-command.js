/**
 * Build one-shot VPS provision curl commands for the MPA frontend or AI agents.
 *
 * Usage (Node):
 *   const { buildProvisionCommand } = require('./provision-command.js');
 *   console.log(buildProvisionCommand({ nodeMgtKey: '0x...', vpsIp: '203.0.113.50' }));
 */

'use strict';

const DEFAULT_REPO = 'ContinuumDAO/mpc-config';
const DEFAULT_SCRIPT = 'scripts/install-node-debian-ubuntu.sh';

/**
 * Normalize Ethereum address to 0x + 40 lowercase hex.
 * @param {string} addr
 * @returns {string}
 */
function normalizeEthAddress(addr) {
  if (typeof addr !== 'string') {
    throw new Error('nodeMgtKey must be a string');
  }
  let body = addr.trim();
  if (/^0x/i.test(body)) {
    body = body.slice(2);
  }
  if (!/^[0-9a-fA-F]{40}$/.test(body)) {
    throw new Error('nodeMgtKey must be 0x followed by 40 hex characters');
  }
  const placeholder = '1234567890abcdef1234567890abcdef12345678';
  if (body.toLowerCase() === placeholder) {
    throw new Error('nodeMgtKey cannot be the documentation placeholder address');
  }
  return '0x' + body.toLowerCase();
}

/**
 * Shell-escape a string for use inside double quotes in bash.
 * @param {string} s
 * @returns {string}
 */
function shellQuote(s) {
  return `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$').replace(/`/g, '\\`')}"`;
}

/**
 * @typedef {Object} ProvisionCommandOptions
 * @property {string} [ref='main'] - Git branch for script URL and clone (default main; updates via MPA Maintenance git pull)
 * @property {string} [repo=DEFAULT_REPO] - GitHub org/repo
 * @property {string} [nodeMgtKey] - Ethereum NodeMgtKey
 * @property {string} [publicMgtKey] - Ed25519 public key (64 hex or ssh-ed25519 line)
 * @property {string} vpsIp - Public IPv4 of the VPS (--ip)
 * @property {'on-vps'|'via-ssh'} [delivery='on-vps'] - Command A (on VPS) or B (pipe via SSH)
 * @property {boolean} [installSystemd=true]
 * @property {boolean} [noLoopback=false]
 * @property {boolean} [noFirewall=false]
 * @property {string} [httpPort]
 * @property {string} [relayHost]
 */

/**
 * @param {ProvisionCommandOptions} opts
 * @returns {string}
 */
function buildProvisionCommand(opts) {
  const o = opts || {};
  const ref = o.ref || 'main';
  const repo = o.repo || DEFAULT_REPO;
  const delivery = o.delivery || 'on-vps';
  const vpsIp = (o.vpsIp || '').trim();

  if (!vpsIp) {
    throw new Error('vpsIp is required');
  }
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(vpsIp) && !/^[a-zA-Z0-9.-]+$/.test(vpsIp)) {
    throw new Error('vpsIp must be a valid IPv4 address or hostname');
  }

  const hasEth = o.nodeMgtKey != null && String(o.nodeMgtKey).trim() !== '';
  const hasPub = o.publicMgtKey != null && String(o.publicMgtKey).trim() !== '';
  if (!hasEth && !hasPub) {
    throw new Error('provide nodeMgtKey and/or publicMgtKey (at least one required)');
  }

  const args = [];
  if (hasEth) {
    args.push('--node-mgt-key', normalizeEthAddress(o.nodeMgtKey));
  }
  if (hasPub) {
    args.push('--public-mgt-key', String(o.publicMgtKey).trim());
  }
  args.push('--ip', vpsIp);
  // systemd is enabled by default in install-node-debian-ubuntu.sh — do not emit --install-systemd
  // (avoids failures with older cached copies of the install script on raw.githubusercontent.com).
  if (o.installSystemd === false) {
    args.push('--no-systemd');
  }
  if (o.noLoopback) {
    args.push('--no-loopback');
  }
  if (o.noFirewall) {
    args.push('--no-firewall');
  }
  if (o.httpPort) {
    args.push('--http-port', String(o.httpPort));
  }
  if (o.relayHost) {
    args.push('--relay-host', String(o.relayHost));
  }

  const scriptUrl =
    `https://raw.githubusercontent.com/${repo}/${ref}/${DEFAULT_SCRIPT}`;
  const argStr = args.map(shellQuote).join(' \\\n      ');

  const curlPipe = `curl -fsSL ${shellQuote(scriptUrl)} \\\n  | bash -s -- \\\n      ${argStr}`;

  if (delivery === 'on-vps') {
    return curlPipe;
  }
  if (delivery === 'via-ssh') {
    return curlPipe.replace(
      '| bash -s --',
      `| ssh -o StrictHostKeyChecking=accept-new root@${vpsIp} bash -s --`,
    );
  }
  throw new Error('delivery must be "on-vps" or "via-ssh"');
}

/**
 * @param {ProvisionCommandOptions} opts
 * @returns {{ onVps: string, viaSsh: string }}
 */
function buildProvisionCommands(opts) {
  return {
    onVps: buildProvisionCommand({ ...opts, delivery: 'on-vps' }),
    viaSsh: buildProvisionCommand({ ...opts, delivery: 'via-ssh' }),
  };
}

/**
 * SSH command to set mpcnode login password securely (run from operator's PC as root over SSH).
 * @param {{ vpsIp: string, mpcUser?: string }} opts
 * @returns {string}
 */
function buildSetMpcPasswordSshCommand(opts) {
  const o = opts || {};
  const vpsIp = (o.vpsIp || '').trim();
  const mpcUser = o.mpcUser || 'mpcnode';
  if (!vpsIp) {
    throw new Error('vpsIp is required');
  }
  return `ssh root@${vpsIp} 'passwd ${mpcUser}'`;
}

module.exports = {
  buildProvisionCommand,
  buildProvisionCommands,
  buildSetMpcPasswordSshCommand,
  normalizeEthAddress,
  shellQuote,
  DEFAULT_REPO,
  DEFAULT_SCRIPT,
};
