import { createDockerDesktopClient } from '@docker/extension-api-client'

const ddClient = createDockerDesktopClient()

/** Same ref as VPS one-shot; extension curl-pipes this script into WSL / host shell. */
export const DESKTOP_ORCHESTRATE_SCRIPT_URL =
  'https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh'

/** Standard desktop mpc-config location (WSL $HOME/mpc-config on Windows; ~/mpc-config on macOS). */
export const MPC_DESKTOP_REPO_DISPLAY_PATH = '~/mpc-config'

const form = document.getElementById('install-form')
const installBtn = document.getElementById('install-btn')
const logPanel = document.getElementById('log-panel')
const logOutput = document.getElementById('log-output')
const resultPanel = document.getElementById('result-panel')
const wslDistroRow = document.getElementById('wsl-distro-row')
const wslDistroInput = document.getElementById('wsl-distro')

function appendLog(text) {
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

  return [
    `curl -fsSL ${shSingleQuote(DESKTOP_ORCHESTRATE_SCRIPT_URL)}`,
    '| bash -s --',
    ...args,
  ].join(' ')
}

function showError(message) {
  resultPanel.hidden = false
  resultPanel.className = 'result-panel error'
  resultPanel.textContent = message
}

async function detectWslOnHost() {
  try {
    const result = await ddClient.extension.host.cli.exec('wsl', ['--status'])
    return result?.code === 0
  } catch {
    return false
  }
}

async function detectWindowsHost() {
  try {
    const result = await ddClient.extension.host.cli.exec('cmd', ['/c', 'ver'])
    return result?.code === 0
  } catch {
    return false
  }
}

async function runInstallOnHost(shellCommand, { useWsl, wslDistro }) {
  const stream = {
    onOutput({ stdout, stderr }) {
      if (stdout) appendLog(stdout)
      if (stderr) appendLog(stderr)
    },
  }

  if (useWsl) {
    return ddClient.extension.host.cli.exec(
      'wsl',
      ['-d', wslDistro, 'bash', '-lc', shellCommand],
      { stream },
    )
  }

  return ddClient.extension.host.cli.exec('bash', ['-lc', shellCommand], { stream })
}

void (async () => {
  const isWindows = await detectWindowsHost()
  const hasWsl = await detectWslOnHost()
  if (isWindows && wslDistroRow) {
    wslDistroRow.hidden = false
    if (!hasWsl) {
      showError(
        'WSL is required on Windows. Install a Linux distro, enable WSL integration in Docker Desktop, then retry.',
      )
    }
  }
})()

form.addEventListener('submit', async (event) => {
  event.preventDefault()
  resultPanel.hidden = true
  resultPanel.textContent = ''
  logPanel.hidden = false
  logOutput.textContent = ''
  installBtn.disabled = true

  const nodeMgtKey = document.getElementById('node-mgt-key').value
  const publicMgtKey = document.getElementById('public-mgt-key').value
  const nodeIp = document.getElementById('node-ip').value

  let shellCommand
  try {
    shellCommand = buildOrchestrateShellCommand({ nodeMgtKey, publicMgtKey, nodeIp })
  } catch (err) {
    showError(err instanceof Error ? err.message : String(err))
    installBtn.disabled = false
    return
  }

  const isWindows = await detectWindowsHost()
  const hasWsl = await detectWslOnHost()

  if (isWindows && !hasWsl) {
    showError(
      'WSL is required on Windows. Install a Linux distro and enable Docker Desktop WSL integration for it.',
    )
    installBtn.disabled = false
    return
  }

  const useWsl = isWindows || hasWsl
  const wslDistro = (wslDistroInput?.value ?? 'Ubuntu').trim()

  if (useWsl && !isValidWslDistroName(wslDistro)) {
    showError('Enter a valid WSL distro name (e.g. Ubuntu-24.04). Run wsl -l -v in PowerShell.')
    installBtn.disabled = false
    return
  }

  appendLog(
    useWsl
      ? `Using WSL distro "${wslDistro}" — clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`
      : `Clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`,
  )

  try {
    const result = await runInstallOnHost(shellCommand, { useWsl, wslDistro })

    resultPanel.hidden = false
    if (result?.code === 0) {
      resultPanel.className = 'result-panel success'
      const repoHint = useWsl
        ? `<code>${MPC_DESKTOP_REPO_DISPLAY_PATH}</code> in WSL (${wslDistro})`
        : `<code>${MPC_DESKTOP_REPO_DISPLAY_PATH}</code>`
      resultPanel.innerHTML =
        '<p><strong>Install finished.</strong> mpc-config is at ' +
        repoHint +
        '. Stack containers (mongo, mpc-auth, continuum-mcp, continuumdao-node-app) appear in Docker Desktop → Containers. ' +
        'Open continuumdao-node-app at <code>http://127.0.0.1:3333</code> for Plain HTTP attach. ' +
        'Back up <code>bootstrap_key/</code> under that WSL directory if a new key was generated.</p>'
    } else {
      showError(`Install failed (exit ${result?.code ?? 'unknown'}). See log above.`)
    }
  } catch (err) {
    showError(err instanceof Error ? err.message : String(err))
  } finally {
    installBtn.disabled = false
  }
})
