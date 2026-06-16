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

/** Shipped host binary (metadata.json host.binaries) — sole Windows WSL entry point. */
const WSL_HOST_WRAPPER = 'continuum-wsl.cmd'

/** Temp path inside WSL / macOS host for the downloaded orchestrator (no curl|bash pipe — SDK forbids shell operators). */
const ORCHESTRATE_SCRIPT_PATH = '/tmp/continuum-desktop-orchestrate.sh'

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

const PROGRESS_PREFIX = '@continuum/progress\t'
const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

function createProgressTracker({ progressPanel, progressTopics, progressOverall }) {
  const topics = new Map()
  let overallPct = 0
  let spinnerOn = false
  let spinnerIdx = 0
  let spinnerTimer = null

  function topicLabel(id, fallback) {
    const t = topics.get(id)
    return t?.label ?? fallback ?? id
  }

  function renderRow(id, label, pct, state) {
    const row = document.createElement('div')
    row.className = 'install-progress-row'
    row.dataset.topicId = id

    const labelEl = document.createElement('span')
    labelEl.className = 'install-progress-label'
    if (state === 'done' || state === 'skipped') labelEl.classList.add('is-done')
    if (state === 'failed') labelEl.classList.add('is-failed')
    labelEl.textContent = label
    labelEl.title = label

    const track = document.createElement('div')
    track.className = 'install-progress-track'
    const fill = document.createElement('div')
    fill.className = 'install-progress-fill'
    if (state === 'active') fill.classList.add('is-active')
    if (state === 'failed') fill.classList.add('is-failed')
    fill.style.width = `${Math.max(0, Math.min(100, pct))}%`
    track.appendChild(fill)

    const pctEl = document.createElement('span')
    pctEl.className = 'install-progress-pct'
    pctEl.textContent = `${Math.round(pct)}%`

    row.append(labelEl, track, pctEl)
    return row
  }

  function renderOverall() {
    if (!progressOverall) return
    progressOverall.replaceChildren()

    const row = document.createElement('div')
    row.className = 'install-progress-overall-row'

    const labelEl = document.createElement('span')
    labelEl.className = 'install-progress-label font-medium'
    labelEl.textContent = 'Overall'

    const track = document.createElement('div')
    track.className = 'install-progress-track'
    const fill = document.createElement('div')
    fill.className = 'install-progress-fill'
    if (spinnerOn) fill.classList.add('is-active')
    fill.style.width = `${Math.max(0, Math.min(100, overallPct))}%`
    track.appendChild(fill)

    const tail = document.createElement('span')
    tail.className = 'install-progress-pct flex items-center justify-end gap-1'
    tail.innerHTML = `<span>${Math.round(overallPct)}%</span>`
    if (spinnerOn) {
      const spin = document.createElement('span')
      spin.className = 'install-progress-spinner'
      spin.textContent = SPINNER_FRAMES[spinnerIdx % SPINNER_FRAMES.length]
      spin.setAttribute('aria-hidden', 'true')
      tail.appendChild(spin)
    }

    row.append(labelEl, track, tail)
    progressOverall.appendChild(row)
  }

  function renderAll() {
    if (!progressTopics) return
    progressTopics.replaceChildren()
    for (const [id, t] of topics) {
      progressTopics.appendChild(renderRow(id, t.label, t.pct ?? 0, t.state ?? 'pending'))
    }
    renderOverall()
  }

  function showPanel() {
    if (!progressPanel) return
    progressPanel.hidden = false
    progressPanel.classList.remove('hidden')
  }

  function startSpinner() {
    if (spinnerTimer) return
    spinnerTimer = window.setInterval(() => {
      spinnerIdx = (spinnerIdx + 1) % SPINNER_FRAMES.length
      renderOverall()
    }, 120)
  }

  function stopSpinner() {
    if (spinnerTimer) {
      window.clearInterval(spinnerTimer)
      spinnerTimer = null
    }
  }

  function handleEvent(ev) {
    if (!ev || typeof ev !== 'object') return
    switch (ev.type) {
      case 'init':
        topics.clear()
        for (const t of ev.topics ?? []) {
          if (!t?.id) continue
          topics.set(t.id, { label: t.label ?? t.id, pct: 0, state: 'pending', weight: t.weight ?? 1 })
        }
        showPanel()
        renderAll()
        break
      case 'topic': {
        if (!ev.id) break
        const cur = topics.get(ev.id) ?? { label: ev.id, pct: 0, state: 'pending' }
        cur.pct = typeof ev.pct === 'number' ? ev.pct : cur.pct
        cur.state = ev.state ?? cur.state
        topics.set(ev.id, cur)
        showPanel()
        renderAll()
        break
      }
      case 'overall':
        overallPct = typeof ev.pct === 'number' ? ev.pct : overallPct
        spinnerOn = ev.spinner === true
        if (spinnerOn) startSpinner()
        else stopSpinner()
        showPanel()
        renderOverall()
        break
      case 'finish':
        spinnerOn = false
        stopSpinner()
        if (ev.ok === true) overallPct = 100
        renderAll()
        break
      default:
        break
    }
  }

  function reset() {
    topics.clear()
    overallPct = 0
    spinnerOn = false
    spinnerIdx = 0
    stopSpinner()
    if (progressTopics) progressTopics.replaceChildren()
    if (progressOverall) progressOverall.replaceChildren()
    if (progressPanel) {
      progressPanel.hidden = true
      progressPanel.classList.add('hidden')
    }
  }

  return { handleEvent, reset, topicLabel }
}

function parseProgressLines(text, progressTracker, logOutput) {
  let rest = text
  let idx
  while ((idx = rest.indexOf(PROGRESS_PREFIX)) !== -1) {
    const before = rest.slice(0, idx)
    if (before && logOutput) appendLog(logOutput, before)
    rest = rest.slice(idx + PROGRESS_PREFIX.length)
    const lineEnd = rest.indexOf('\n')
    const jsonLine = lineEnd === -1 ? rest : rest.slice(0, lineEnd)
    rest = lineEnd === -1 ? '' : rest.slice(lineEnd + 1)
    try {
      progressTracker.handleEvent(JSON.parse(jsonLine))
    } catch {
      if (logOutput) appendLog(logOutput, `${PROGRESS_PREFIX}${jsonLine}\n`)
    }
  }
  if (rest && logOutput) appendLog(logOutput, rest)
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

function buildOrchestrateScriptArgs({ nodeMgtKey, publicMgtKey, nodeIp }) {
  const eth = nodeMgtKey.trim()
  const pub = publicMgtKey.trim()
  const ip = nodeIp.trim()

  if (!eth && !pub) {
    throw new Error('Provide NodeMgtKey and/or PublicMgtKey')
  }
  if (!ip) {
    throw new Error('Public IPv4 is required')
  }

  const scriptArgs = []
  if (eth) {
    scriptArgs.push('--node-mgt-key', eth)
  }
  if (pub) {
    scriptArgs.push('--public-mgt-key', pub)
  }
  scriptArgs.push('--ip', ip)
  return scriptArgs
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

function wslHostArgs(distro, tailArgs) {
  return ['-d', distro, ...tailArgs]
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

  const probe = await execHostSimple(cli, WSL_HOST_WRAPPER, ['-l', '-v'])
  if (!probe.ok || !probe.result) {
    return { isWindows: true, wslAvailable: false, distros: [], defaultDistro: null, listOutput: '' }
  }

  const listOutput = combinedExecOutput(probe.result)
  if (!listOutput || /no installed distributions/i.test(listOutput)) {
    return { isWindows: true, wslAvailable: false, distros: [], defaultDistro: null, listOutput: '' }
  }

  const { distros, defaultDistro } = parseWslDistroList(listOutput)
  return {
    isWindows: true,
    wslAvailable: distros.length > 0,
    distros,
    defaultDistro,
    listOutput,
  }
}

/**
 * host.cli.exec with { stream } returns ExecProcess, not a Promise — wrap onClose.
 */
function execHostStreaming(cli, cmd, args, logOutput, progressTracker) {
  return new Promise((resolve, reject) => {
    let settled = false
    let stdoutBuf = ''

    const flushStdout = (final = false) => {
      if (!stdoutBuf) return
      if (progressTracker) {
        parseProgressLines(stdoutBuf, progressTracker, logOutput)
        stdoutBuf = ''
        return
      }
      if (final || stdoutBuf.includes('\n')) {
        appendLog(logOutput, stdoutBuf.endsWith('\n') ? stdoutBuf : `${stdoutBuf}\n`)
        stdoutBuf = ''
      }
    }

    const finish = (exitCode) => {
      if (settled) return
      settled = true
      if (progressTracker && stdoutBuf) {
        const line = stdoutBuf
        stdoutBuf = ''
        if (line.startsWith(PROGRESS_PREFIX)) {
          try {
            progressTracker.handleEvent(JSON.parse(line.slice(PROGRESS_PREFIX.length)))
          } catch {
            appendLog(logOutput, `${line}\n`)
          }
        } else if (line.length > 0) {
          appendLog(logOutput, `${line}\n`)
        }
      } else {
        flushStdout(true)
      }
      appendLog(logOutput, `\n[process exited ${exitCode}]\n`)
      resolve({ code: exitCode })
    }

    const stream = {
      onOutput({ stdout, stderr }) {
        if (stdout) {
          if (progressTracker) {
            stdoutBuf += stdout
            let nl
            while ((nl = stdoutBuf.indexOf('\n')) !== -1) {
              const line = stdoutBuf.slice(0, nl)
              stdoutBuf = stdoutBuf.slice(nl + 1)
              if (line.startsWith(PROGRESS_PREFIX)) {
                try {
                  progressTracker.handleEvent(JSON.parse(line.slice(PROGRESS_PREFIX.length)))
                } catch {
                  appendLog(logOutput, `${line}\n`)
                }
              } else if (line.length > 0) {
                appendLog(logOutput, `${line}\n`)
              }
            }
          } else {
            appendLog(logOutput, stdout.endsWith('\n') ? stdout : `${stdout}\n`)
          }
        }
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

async function verifyWslDistro(cli, wslDistro, logOutput) {
  appendLog(logOutput, `Checking WSL distro "${wslDistro}" via ${WSL_HOST_WRAPPER}…\n`)

  const probe = await execHostSimple(cli, WSL_HOST_WRAPPER, wslHostArgs(wslDistro, ['-e', 'echo', 'ok']))
  if (!probe.ok) {
    appendLog(
      logOutput,
      `[host exec error: ${probe.error instanceof Error ? probe.error.message : String(probe.error)}]\n`,
    )
    return false
  }

  const out = combinedExecOutput(probe.result)
  const code = probe.result?.code
  appendLog(logOutput, `[exit ${code ?? 'unknown'}]${out ? ` ${out}` : ''}\n`)

  if (execSucceeded(probe.result, { expectSubstring: 'ok' })) {
    appendLog(logOutput, `WSL distro "${wslDistro}" is reachable.\n\n`)
    return true
  }

  return false
}

async function runInstallOnHost(cli, { useWsl, wslDistro, scriptArgs }, logOutput, progressTracker) {
  appendLog(logOutput, 'Downloading orchestrator script…\n')

  const curlArgs = useWsl
    ? wslHostArgs(wslDistro, ['curl', '-fsSL', DESKTOP_ORCHESTRATE_SCRIPT_URL, '-o', ORCHESTRATE_SCRIPT_PATH])
    : ['-fsSL', DESKTOP_ORCHESTRATE_SCRIPT_URL, '-o', ORCHESTRATE_SCRIPT_PATH]

  let result = await execHostStreaming(
    cli,
    useWsl ? WSL_HOST_WRAPPER : 'curl',
    curlArgs,
    logOutput,
    null,
  )
  if (result.code !== 0) {
    return result
  }

  appendLog(logOutput, `\nRunning orchestrator via ${useWsl ? WSL_HOST_WRAPPER : 'bash'}…\n\n`)

  const runArgs = useWsl
    ? wslHostArgs(wslDistro, [
        'env',
        'CONTINUUM_INSTALL_PROGRESS=json',
        'bash',
        ORCHESTRATE_SCRIPT_PATH,
        ...scriptArgs,
      ])
    : ['env', 'CONTINUUM_INSTALL_PROGRESS=json', 'bash', ORCHESTRATE_SCRIPT_PATH, ...scriptArgs]

  return execHostStreaming(
    cli,
    useWsl ? WSL_HOST_WRAPPER : 'bash',
    runArgs,
    logOutput,
    progressTracker,
  )
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
  const progressPanel = document.getElementById('progress-panel')
  const progressTopics = document.getElementById('progress-topics')
  const progressOverall = document.getElementById('progress-overall')
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
  const progressTracker = createProgressTracker({ progressPanel, progressTopics, progressOverall })
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

    if (wslEnv.isWindows) {
      showStatus(
        bootStatus,
        'Ready — enter the exact WSL distro name from wsl -l -v (e.g. Ubuntu-26.04), keys, and public IPv4.',
      )
      showError(
        resultPanel,
        `Could not list WSL distros via ${WSL_HOST_WRAPPER}. Reinstall the extension so Docker copies the host binary, then quit and restart Docker Desktop.`,
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
    progressTracker.reset()
    installBtn.disabled = true

    const nodeMgtKey = document.getElementById('node-mgt-key')?.value ?? ''
    const publicMgtKey = document.getElementById('public-mgt-key')?.value ?? ''
    const nodeIp = document.getElementById('node-ip')?.value ?? ''

    let scriptArgs
    try {
      scriptArgs = buildOrchestrateScriptArgs({ nodeMgtKey, publicMgtKey, nodeIp })
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

    if (useWsl) {
      const distroOk = await verifyWslDistro(cli, wslDistro, logOutput)
      if (!distroOk) {
        showError(
          resultPanel,
          `Could not run commands in WSL distro "${wslDistro}" via ${WSL_HOST_WRAPPER}. Confirm the distro name matches wsl -l -v exactly. Reinstall the extension if the host binary is missing.`,
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
        result = await runInstallOnHost(cli, { useWsl: true, wslDistro, scriptArgs }, logOutput, progressTracker)
      } else {
        result = await runInstallOnHost(cli, { useWsl: false, wslDistro: null, scriptArgs }, logOutput, progressTracker)
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
