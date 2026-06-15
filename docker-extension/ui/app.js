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

/** Standard desktop mpc-config location (WSL $HOME/mpc-config on Windows; ~/mpc-config on macOS). */
const MPC_DESKTOP_REPO_DISPLAY_PATH = '~/mpc-config'

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

/** Safe single-quoted string for bash -lc on WSL / macOS host. */
function shSingleQuote(value) {
  return `'${String(value).replace(/'/g, `'\"'\"'`)}'`
}

function isValidWslDistroName(name) {
  const trimmed = name.trim()
  if (!trimmed || trimmed.length > 64) return false
  return /^[\w.-]+$/.test(trimmed)
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

  // Single bash -lc string so curl|bash pipe runs inside WSL, not in host.cli.exec itself.
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

async function detectWslOnHost(cli) {
  try {
    const result = await cli.exec('wsl', ['--status'])
    return result?.code === 0
  } catch {
    return false
  }
}

function isWindowsPlatform(ddClient) {
  const platform = ddClient?.host?.platform ?? ddClient?.desktopUI?.host?.platform
  if (platform === 'win32') return true
  if (platform === 'darwin' || platform === 'linux') return false
  return null
}

async function detectWindowsHost(cli, ddClient) {
  const fromPlatform = isWindowsPlatform(ddClient)
  if (fromPlatform === true) return true
  if (fromPlatform === false) return false
  try {
    const result = await cli.exec('cmd', ['/c', 'ver'])
    return result?.code === 0
  } catch {
    return false
  }
}

async function runInstallOnHost(cli, shellCommand, { useWsl, wslDistro }, logOutput) {
  const stream = {
    onOutput({ stdout, stderr }) {
      if (stdout) appendLog(logOutput, stdout)
      if (stderr) appendLog(logOutput, stderr)
    },
    onError(error) {
      appendLog(logOutput, `\n[stream error] ${error?.message ?? String(error)}\n`)
    },
    onClose(exitCode) {
      appendLog(logOutput, `\n[process exited ${exitCode}]\n`)
    },
  }

  if (useWsl) {
    return cli.exec('wsl', ['-d', wslDistro, 'bash', '-lc', shellCommand], { stream })
  }

  return cli.exec('bash', ['-lc', shellCommand], { stream })
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
    showStatus(bootStatus, 'Ready — enter keys and public IPv4, then Install node.')
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

  void (async () => {
    const isWindows = await detectWindowsHost(cli, ddClient)
    const hasWsl = await detectWslOnHost(cli)
    if (isWindows && wslDistroRow) {
      wslDistroRow.hidden = false
      if (!hasWsl) {
        showError(
          resultPanel,
          'WSL is required on Windows. Install a Linux distro, enable WSL integration in Docker Desktop, then retry.',
        )
      }
    }
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

    const isWindows = await detectWindowsHost(cli, ddClient)
    const hasWsl = await detectWslOnHost(cli)

    if (isWindows && !hasWsl) {
      showError(
        resultPanel,
        'WSL is required on Windows. Install a Linux distro and enable Docker Desktop WSL integration for it.',
      )
      installBtn.disabled = false
      return
    }

    const useWsl = isWindows || hasWsl
    const wslDistro = (wslDistroInput?.value ?? 'Ubuntu').trim()

    if (useWsl && !isValidWslDistroName(wslDistro)) {
      showError(resultPanel, 'Enter a valid WSL distro name (e.g. Ubuntu-24.04). Run wsl -l -v in PowerShell.')
      installBtn.disabled = false
      return
    }

    appendLog(
      logOutput,
      useWsl
        ? `Using WSL distro "${wslDistro}" — clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`
        : `Clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`,
    )

    try {
      const result = await runInstallOnHost(cli, shellCommand, { useWsl, wslDistro }, logOutput)

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
