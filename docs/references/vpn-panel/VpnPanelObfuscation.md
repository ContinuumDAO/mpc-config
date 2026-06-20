# VPN Panel: Shadowsocks obfuscation UI (continuumdao-node-app)

Reference implementation for the **VPN Panel** in [continuumdao-node-app](https://github.com/ContinuumDAO/continuumdao-node-app). Wire to existing `/vpn/*` management API calls.

## Status type extension

```typescript
export type VpnObfuscation = 'none' | 'shadowsocks';

export interface VpnStatus {
  available: boolean;
  active: boolean;
  profile: 'split' | 'full' | '';
  obfuscation?: VpnObfuscation;
  obfuscationAvailable?: boolean;
  shadowsocksListenPort?: number;
  shadowsocksMethod?: string;
  directWireGuardBlocked?: boolean;
  endpointHost?: string;
  listenPort?: number;
  // ...existing fields
}
```

## Obfuscation toggle

Show only when `status.available && status.obfuscationAvailable`:

```tsx
<label className="flex items-center gap-2">
  <input
    type="checkbox"
    checked={obfuscation === 'shadowsocks'}
    disabled={!status.obfuscationAvailable || vpnBusy}
    onChange={(e) =>
      setObfuscation(e.target.checked ? 'shadowsocks' : 'none')
    }
  />
  Obfuscate WireGuard (Shadowsocks)
</label>
{obfuscation === 'shadowsocks' && (
  <p className="text-sm text-amber-600">
    Requires sslocal on your workstation. Direct UDP WireGuard will not work.
  </p>
)}
```

## `POST /vpn/setEnabled`

Include `obfuscation` when enabling:

```typescript
async function setVpnEnabled(
  enabled: boolean,
  profile: 'split' | 'full',
  obfuscation: VpnObfuscation,
) {
  await signedPost('/vpn/setEnabled', {
    enabled,
    profile,
    obfuscation: enabled ? obfuscation : 'none',
  });
}
```

## Download client config

When `status.obfuscation === 'shadowsocks'` (or user selected obfuscation on enable):

```typescript
interface VpnClientBundle {
  wireGuardConfigText?: string;
  shadowsocksLocalConfigText?: string;
  shadowsocksUri?: string;
  setupInstructions?: string;
  filename?: string;
  shadowsocksLocalFilename?: string;
  configText?: string; // legacy when obfuscation none
}

async function downloadVpnConfig(profile: 'split' | 'full') {
  const { data } = await signedPost<VpnClientBundle>('/vpn/clientConfig', { profile });

  if (data.shadowsocksLocalConfigText) {
    downloadBlob(data.shadowsocksLocalConfigText, data.shadowsocksLocalFilename ?? 'continuum-sslocal.json');
    downloadBlob(data.wireGuardConfigText ?? '', data.filename ?? 'continuum-wg0-obfuscated.conf');
    if (data.setupInstructions) {
      alert(data.setupInstructions);
    }
  } else {
    downloadBlob(data.configText ?? '', data.filename ?? 'continuum-wg0.conf');
  }
}
```

## Status display

When active with obfuscation:

```tsx
{status.active && status.obfuscation === 'shadowsocks' && (
  <div>
    Obfuscation: Shadowsocks (port {status.shadowsocksListenPort ?? 8388})
    {status.directWireGuardBlocked && ' — direct WireGuard UDP blocked'}
  </div>
)}
```

## Operator commands (help text)

```text
sslocal -c continuum-sslocal.json
wg-quick up continuum-wg0-obfuscated.conf
```

Install client tools: [shadowsocks-rust releases](https://github.com/shadowsocks/shadowsocks-rust/releases) (`sslocal` binary).

## Polling

Reuse existing `GET /vpn/status` poll interval; no new endpoints required.
