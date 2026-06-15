import { createDockerDesktopClient } from '@docker/extension-api-client'
import './globals.css'

const BOOT_STATUS_BASE =
  'm-0 rounded-[4px] border px-3 py-2 font-sans text-[0.8125rem]'
const BOOT_STATUS_OK = `${BOOT_STATUS_BASE} border-[var(--muted)] text-[var(--muted)]`
const BOOT_STATUS_ERR = `${BOOT_STATUS_BASE} border-[color-mix(in_srgb,var(--accent3)_55%,var(--muted))] text-[var(--accent3)]`

const RESULT_PANEL_BASE =
  'm-0 rounded-[4px] border bg-[color-mix(in_srgb,var(--surface)_88%,var(--bg))] p-3 font-sans text-[0.8125rem] leading-relaxed'
const RESULT_PANEL_OK = `${RESULT_PANEL_BASE} border-[color-mix(in_srgb,var(--accent2)_55%,var(--muted))] text-[var(--text)]`
const RESULT_PANEL_ERR = `${RESULT_PANEL_BASE} border-[color-mix(in_srgb,var(--accent3)_55%,var(--muted))] text-[var(--accent3)]`

const LOG_PANEL_VISIBLE = 'flex flex-col gap-2'
const DESKTOP_ORCHESTRATE_SCRIPT_URL =
  'https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh'

/** Shipped in metadata.json host.binaries — Docker copies this beside the extension on Windows. */
const WSL_HOST_WRAPPER = 'continuum-wsl.cmd'

/** Standard desktop mpc-config location (WSL $HOME/mpc-config on Windows; ~/mpc-config on macOS). */
const MPC_DESKTOP_REPO_DISPLAY_PATH = '~/mpc-config'

const WSL_SKIP_DISTROS = new Set(['docker-desktop', 'docker-desktop-data'])

function getHostCli() {
  const ddClient = createDockerDesktopClient()
  const cli = ddClient?.extension?.host?.cli
  if (!cli?.exec) {
    throw new Error('Docker Desktop host CLI API unavailable — update Docker Desktop and reload the extension.')
  }
  return { ddClient, cli }
}

function appendLog(logOutput, text) {
  logOutput.textContent += text
  logOutput.scrollTop = logOutput.scrollHeight
}

function normalizeHostOutput(text) {
  return String(text ?? '')
    .replace(/\u0000/g, '')
    .trim()
}

function combinedExecOutput(result) {
  return normalizeHostOutput(`${result?.stdout ?? ''}${result?.stderr ?? ''}`)
}

/** Safe single-quoted string for bash -lc on WSL / macOS host. */
function shSingleQuote(value) {
  return `'${String(value).replace(/'/g, `'\"'\"'`)}'`
}

function isValidWslDistroName(name) {
  const trimmed = name.trim()
  if (!trimmed || trimmed.length > 64) return false
  return /^[\w.-]+$/.test(trimmed)
}

function parseWslDistroList(text) {
  const distros = []
  let defaultDistro = null
  const normalized = normalizeHostOutput(text)

  for (const line of normalized.split(/\r?\n/)) {
    const match = line.match(/^\s*(\*?)\s*([^\s]+)\s+/)
    if (!match) continue

    const star = match[1]
    const name = match[2]
    if (name === 'NAME' || WSL_SKIP_DISTROS.has(name)) continue

    distros.push(name)
    if (star === '*') {
      defaultDistro = name
    }
  }

  return {
    distros,
    defaultDistro: defaultDistro ?? distros[0] ?? null,
  }
}

function buildOrchestrateShellCommand({ nodeMgtKey, publicMgtKey, nodeIp }) {
  const eth = nodeMgtKey.trim()
  const pub = publicMgtKey.trim()
  const ip = nodeIp.trim()

  if (!eth && !pub) {
    throw new Error('Provide NodeMgtKey and/or PublicMgtKey')
  }
  if (!ip) {
    throw new Error('Public IPv4 is required')
  }

  const args = []
  if (eth) {
    args.push('--node-mgt-key', shSingleQuote(eth))
  }
  if (pub) {
    args.push('--public-mgt-key', shSingleQuote(pub))
  }
  args.push('--ip', shSingleQuote(ip))

  return [
    `curl -fsSL ${shSingleQuote(DESKTOP_ORCHESTRATE_SCRIPT_URL)}`,
    '| bash -s --',
    ...args,
  ].join(' ')
}

function showError(resultPanel, message) {
  resultPanel.hidden = false
  resultPanel.className = RESULT_PANEL_ERR
  resultPanel.textContent = message
}

function showStatus(bootStatus, message, isError = false) {
  if (!bootStatus) return
  bootStatus.hidden = false
  bootStatus.className = isError ? BOOT_STATUS_ERR : BOOT_STATUS_OK
  bootStatus.textContent = message
}

function showLogPanel(logPanel) {
  logPanel.hidden = false
  logPanel.className = LOG_PANEL_VISIBLE
}

function isWindowsPlatform(ddClient) {
  const platform = ddClient?.host?.platform ?? ddClient?.desktopUI?.host?.platform
  if (platform === 'win32') return true
  if (platform === 'darwin' || platform === 'linux') return false
  return null
}

async function execHostSimple(cli, cmd, args) {
  try {
    const result = await cli.exec(cmd, args)
    return { ok: true, result }
  } catch (error) {
    return { ok: false, error }
  }
}

function execSucceeded(result, { expectSubstring } = {}) {
  if (!result) return false
  const out = combinedExecOutput(result)
  const code = result.code
  if (expectSubstring && out.includes(expectSubstring)) {
    return code === undefined || code === 0 || code === null
  }
  return code === 0
}

/**
 * Docker Desktop host.cli.exec only resolves binaries on PATH or shipped host.binaries.
 * Use continuum-wsl.cmd first, then cmd.exe /c wsl.exe fallbacks.
 */
function buildWindowsWslExecAttempts(distro, tailArgs) {
  const wslArgs = ['-d', distro, ...tailArgs]
  return [
    { label: WSL_HOST_WRAPPER, cmd: WSL_HOST_WRAPPER, args: wslArgs },
    { label: 'cmd.exe → wsl.exe', cmd: 'cmd.exe', args: ['/c', 'wsl.exe', ...wslArgs] },
    { label: 'cmd.exe → wsl', cmd: 'cmd.exe', args: ['/c', 'wsl', ...wslArgs] },
    { label: 'wsl.exe', cmd: 'wsl.exe', args: wslArgs },
    { label: 'wsl', cmd: 'wsl', args: wslArgs },
  ]
}

async function detectWindowsHost(cli, ddClient) {
  const fromPlatform = isWindowsPlatform(ddClient)
  if (fromPlatform === true) return true
  if (fromPlatform === false) return false
  const probe = await execHostSimple(cli, 'cmd', ['/c', 'ver'])
  return probe.ok && probe.result?.code === 0
}

async function probeWslEnvironment(cli, ddClient) {
  const isWindows = await detectWindowsHost(cli, ddClient)
  if (!isWindows) {
    return { isWindows: false, wslAvailable: false, distros: [], defaultDistro: null, listOutput: '' }
  }

  const listAttempts = [
    { cmd: WSL_HOST_WRAPPER, args: ['-l', '-v'] },
    { cmd: 'cmd.exe', args: ['/c', 'wsl.exe', '-l', '-v'] },
    { cmd: 'cmd.exe', args: ['/c', 'wsl', '-l', '-v'] },
    { cmd: 'wsl.exe', args: ['-l', '-v'] },
    { cmd: 'wsl', args: ['-l', '-v'] },
  ]

  let listOutput = ''
  let distros = []
  let defaultDistro = null

  for (const { cmd, args } of listAttempts) {
    const probe = await execHostSimple(cli, cmd, args)
    if (!probe.ok || !probe.result) continue

    const out = combinedExecOutput(probe.result)
    if (!out || /no installed distributions/i.test(out)) continue

    const parsed = parseWslDistroList(out)
    if (parsed.distros.length > 0) {
      listOutput = out
      distros = parsed.distros
      defaultDistro = parsed.defaultDistro
      break
    }

    if (/default version|kernel version|wsl/i.test(out)) {
      listOutput = out
    }
  }

  return {
    isWindows: true,
    wslAvailable: distros.length > 0 || listOutput.length > 0,
    distros,
    defaultDistro,
    listOutput,
  }
}

/**
 * host.cli.exec with { stream } returns ExecProcess, not a Promise — wrap onClose.
 */
function execHostStreaming(cli, cmd, args, logOutput) {
  return new Promise((resolve, reject) => {
    let settled = false

    const finish = (exitCode) => {
      if (settled) return
      settled = true
      appendLog(logOutput, `\n[process exited ${exitCode}]\n`)
      resolve({ code: exitCode })
    }

    const stream = {
      onOutput({ stdout, stderr }) {
        if (stdout) appendLog(logOutput, stdout.endsWith('\n') ? stdout : `${stdout}\n`)
        if (stderr) appendLog(logOutput, stderr.endsWith('\n') ? stderr : `${stderr}\n`)
      },
      onError(error) {
        if (settled) return
        settled = true
        const message = error?.message ?? String(error)
        appendLog(logOutput, `\n[stream error] ${message}\n`)
        reject(error instanceof Error ? error : new Error(message))
      },
      onClose(exitCode) {
        finish(typeof exitCode === 'number' ? exitCode : 1)
      },
    }

    try {
      cli.exec(cmd, args, { stream, splitOutputLines: true })
    } catch (error) {
      reject(error instanceof Error ? error : new Error(String(error)))
    }
  })
}

async function resolveWindowsWslLauncher(cli, distro, logOutput) {
  appendLog(logOutput, `Checking WSL distro "${distro}"…\n`)

  for (const attempt of buildWindowsWslExecAttempts(distro, ['-e', 'echo', 'ok'])) {
    appendLog(logOutput, `Trying ${attempt.label}…\n`)
    const probe = await execHostSimple(cli, attempt.cmd, attempt.args)

    if (!probe.ok) {
      appendLog(
        logOutput,
        `[host exec error: ${probe.error instanceof Error ? probe.error.message : String(probe.error)}]\n`,
      )
      continue
    }

    const out = combinedExecOutput(probe.result)
    const code = probe.result?.code
    appendLog(logOutput, `[exit ${code ?? 'unknown'}]${out ? ` ${out}` : ''}\n`)

    if (execSucceeded(probe.result, { expectSubstring: 'ok' })) {
      appendLog(logOutput, `WSL distro "${distro}" is reachable via ${attempt.label}.\n\n`)
      return attempt
    }
  }

  return null
}

async function verifyWslDistro(cli, wslDistro, wslEnv, logOutput) {
  const launcher = await resolveWindowsWslLauncher(cli, wslDistro, logOutput)
  if (launcher) {
    return launcher
  }

  if (wslEnv.distros.includes(wslDistro)) {
    appendLog(
      logOutput,
      `Echo probe failed, but "${wslDistro}" appears in wsl -l -v — continuing with ${WSL_HOST_WRAPPER}.\n\n`,
    )
    return { label: WSL_HOST_WRAPPER, cmd: WSL_HOST_WRAPPER, args: ['-d', wslDistro] }
  }

  return null
}

async function runInstallOnHost(cli, shellCommand, launcher, wslDistro, logOutput) {
  const tailArgs = ['bash', '-lc', shellCommand]
  const args =
    launcher.cmd === WSL_HOST_WRAPPER || launcher.cmd === 'wsl.exe' || launcher.cmd === 'wsl'
      ? ['-d', wslDistro, ...tailArgs]
      : [...launcher.args.slice(0, launcher.args.indexOf('-d') + 2), ...tailArgs]

  appendLog(logOutput, `Running install via ${launcher.label}…\n\n`)
  return execHostStreaming(cli, launcher.cmd, args, logOutput)
}

function applyDetectedWslDistro(wslDistroInput, wslEnv) {
  if (!wslDistroInput || !wslEnv.defaultDistro) return

  const current = wslDistroInput.value.trim()
  if (!current || current === 'Ubuntu') {
    wslDistroInput.value = wslEnv.defaultDistro
  }
}

function initExtensionUi() {
  const form = document.getElementById('install-form')
  const installBtn = document.getElementById('install-btn')
  const logPanel = document.getElementById('log-panel')
  const logOutput = document.getElementById('log-output')
  const resultPanel = document.getElementById('result-panel')
  const wslDistroRow = document.getElementById('wsl-distro-row')
  const wslDistroInput = document.getElementById('wsl-distro')
  const bootStatus = document.getElementById('boot-status')

  if (!form || !installBtn || !logPanel || !logOutput || !resultPanel) {
    showStatus(bootStatus, 'Extension UI failed to initialize (missing DOM). Rebuild the extension image.', true)
    return
  }

  let hostCli
  try {
    hostCli = getHostCli()
  } catch (err) {
    showStatus(
      bootStatus,
      err instanceof Error ? err.message : String(err),
      true,
    )
    installBtn.disabled = true
    return
  }

  const { ddClient, cli } = hostCli
  let wslEnv = { isWindows: false, wslAvailable: false, distros: [], defaultDistro: null, listOutput: '' }

  void (async () => {
    wslEnv = await probeWslEnvironment(cli, ddClient)

    if (wslEnv.isWindows && wslDistroRow) {
      wslDistroRow.hidden = false
      applyDetectedWslDistro(wslDistroInput, wslEnv)
    }

    if (wslEnv.distros.length > 0) {
      showStatus(
        bootStatus,
        `Ready — detected WSL distros: ${wslEnv.distros.join(', ')}. Enter keys and public IPv4, then Install node.`,
      )
      return
    }

    if (wslEnv.isWindows && wslEnv.wslAvailable) {
      showStatus(
        bootStatus,
        'Ready — WSL detected. Confirm the distro name below matches the output of wsl -l -v, then Install node.',
      )
      return
    }

    if (wslEnv.isWindows) {
      showStatus(
        bootStatus,
        'Ready — enter the exact WSL distro name from wsl -l -v (e.g. Ubuntu-26.04), keys, and public IPv4.',
      )
      showError(
        resultPanel,
        'Could not auto-detect WSL from Docker Desktop. Quit and restart Docker Desktop, then reload this extension. Enter the exact distro name above and click Install.',
      )
      return
    }

    showStatus(bootStatus, 'Ready — enter keys and public IPv4, then Install node.')
  })()

  async function runInstall() {
    resultPanel.hidden = true
    resultPanel.textContent = ''
    showLogPanel(logPanel)
    logOutput.textContent = ''
    installBtn.disabled = true

    const nodeMgtKey = document.getElementById('node-mgt-key')?.value ?? ''
    const publicMgtKey = document.getElementById('public-mgt-key')?.value ?? ''
    const nodeIp = document.getElementById('node-ip')?.value ?? ''

    let shellCommand
    try {
      shellCommand = buildOrchestrateShellCommand({ nodeMgtKey, publicMgtKey, nodeIp })
    } catch (err) {
      showError(resultPanel, err instanceof Error ? err.message : String(err))
      installBtn.disabled = false
      return
    }

    wslEnv = await probeWslEnvironment(cli, ddClient)
    applyDetectedWslDistro(wslDistroInput, wslEnv)

    const useWsl = wslEnv.isWindows
    const wslDistro = (wslDistroInput?.value ?? wslEnv.defaultDistro ?? '').trim()

    if (useWsl && !wslDistro) {
      showError(
        resultPanel,
        'Enter your WSL distro name (run wsl -l -v in PowerShell — e.g. Ubuntu-26.04).',
      )
      installBtn.disabled = false
      return
    }

    if (useWsl && !isValidWslDistroName(wslDistro)) {
      showError(resultPanel, 'Enter a valid WSL distro name (e.g. Ubuntu-26.04). Run wsl -l -v in PowerShell.')
      installBtn.disabled = false
      return
    }

    let launcher = null
    if (useWsl) {
      launcher = await verifyWslDistro(cli, wslDistro, wslEnv, logOutput)
      if (!launcher) {
        showError(
          resultPanel,
          `Could not run commands in WSL distro "${wslDistro}". Quit Docker Desktop completely and start it again (no full PC reboot needed). Confirm the distro name matches wsl -l -v exactly (e.g. Ubuntu-26.04). See install log for probe details.`,
        )
        installBtn.disabled = false
        return
      }
    }

    appendLog(
      logOutput,
      useWsl
        ? `Using WSL distro "${wslDistro}" — clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`
        : `Clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`,
    )

    try {
      let result
      if (useWsl) {
        result = await runInstallOnHost(cli, shellCommand, launcher, wslDistro, logOutput)
      } else {
        result = await execHostStreaming(cli, 'bash', ['-lc', shellCommand], logOutput)
      }

      resultPanel.hidden = false
      if (result?.code === 0) {
        resultPanel.className = RESULT_PANEL_OK
        const repoHint = useWsl
          ? `<code class="font-mono text-[0.6875rem] text-[var(--text)]">${MPC_DESKTOP_REPO_DISPLAY_PATH}</code> in WSL (${wslDistro})`
          : `<code class="font-mono text-[0.6875rem] text-[var(--text)]">${MPC_DESKTOP_REPO_DISPLAY_PATH}</code>`
        resultPanel.innerHTML =
          '<p class="m-0"><strong>Install finished.</strong> mpc-config is at ' +
          repoHint +
          '. Stack containers (mongo, mpc-auth, continuum-mcp, continuumdao-node-app) appear in Docker Desktop → Containers. ' +
          'Open continuumdao-node-app at <code class="font-mono text-[0.6875rem] text-[var(--text)]">http://127.0.0.1:3333</code> for Plain HTTP attach. ' +
          'Back up <code class="font-mono text-[0.6875rem] text-[var(--text)]">bootstrap_key/</code> under that WSL directory if a new key was generated.</p>'
      } else {
        showError(resultPanel, `Install failed (exit ${result?.code ?? 'unknown'}). See log above.`)
      }
    } catch (err) {
      showError(resultPanel, err instanceof Error ? err.message : String(err))
    } finally {
      installBtn.disabled = false
    }
  }

  installBtn.addEventListener('click', () => {
    void runInstall()
  })

  form.addEventListener('submit', (event) => {
    event.preventDefault()
    void runInstall()
  })
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initExtensionUi)
} else {
  initExtensionUi()
}
