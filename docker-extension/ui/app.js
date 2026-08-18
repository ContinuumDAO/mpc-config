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

/** Shipped host wrapper (metadata.json host.binaries) — sole Windows WSL entry point. */
const WSL_HOST_WRAPPER = 'continuum-wsl.cmd'

/** Exit codes from host/windows/preflight-windows.ps1 (via continuum-wsl.cmd preflight). */
const PREFLIGHT_EXIT = {
  OK: 0,
  AV_ACTIVE: 10,
  NETWORK_FAILED: 11,
  DOCKER_WSL_FAILED: 12,
  CONFIG_FAILED: 13,
}

/** Registers Windows logon Scheduled Task for WSL pending-update watcher. */
const REGISTER_WATCHER_HOST_WRAPPER = 'continuum-register-watcher.cmd'

/** Shipped host binary (metadata.json host.binaries) — Linux host PATH delegate. */
const LINUX_HOST_WRAPPER = 'continuum-linux.sh'

/** Shipped host binary (metadata.json host.binaries) — macOS host PATH delegate. */
const MACOS_HOST_WRAPPER = 'continuum-macos.sh'

/** Registers macOS launchd LaunchAgent for pending-update watcher. */
const REGISTER_LAUNCHAGENT_HOST_WRAPPER = 'continuum-register-launchagent.sh'

/** Temp path on the host for the downloaded orchestrator (no curl|bash pipe — SDK forbids shell operators). */
const ORCHESTRATE_SCRIPT_PATH = '/tmp/continuum-desktop-orchestrate.sh'

const HOST_OS = {
  WINDOWS: 'windows',
  LINUX: 'linux',
  MACOS: 'macos',
}

const HOST_OS_LABELS = {
  [HOST_OS.WINDOWS]: 'Windows',
  [HOST_OS.LINUX]: 'Linux',
  [HOST_OS.MACOS]: 'macOS',
}

const MPC_DESKTOP_REPO_DISPLAY_PATH = '~/mpc-config'

const MACOS_READY_STATUS =
  'Ready (macOS) — the macOS install script is now available on Docker Desktop. Requires passwordless sudo for /var/lib/mpc-auth-docker. Enter keys and public IPv4, then Install node.'

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
const PROGRESS_MARKER = '@continuum/progress'
const PROGRESS_EVENT_TYPES = new Set(['init', 'sync', 'topic', 'overall', 'finish'])

function progressPayloadFromLine(line) {
  const trimmed = line.trimEnd()
  if (!trimmed) return null
  if (trimmed.startsWith(PROGRESS_PREFIX)) {
    return trimmed.slice(PROGRESS_PREFIX.length)
  }
  if (trimmed.startsWith(PROGRESS_MARKER)) {
    const rest = trimmed.slice(PROGRESS_MARKER.length).replace(/^\s+/, '')
    return rest || null
  }
  if (trimmed.startsWith('{')) {
    return trimmed
  }
  return null
}

function isProgressPayload(payload) {
  if (!payload) return false
  try {
    const ev = JSON.parse(payload)
    return Boolean(ev && typeof ev === 'object' && PROGRESS_EVENT_TYPES.has(ev.type))
  } catch {
    return false
  }
}

function isProgressStreamLine(line) {
  const payload = progressPayloadFromLine(line)
  return payload !== null && isProgressPayload(payload)
}

function tryHandleProgressLine(line, progressTracker) {
  const payload = progressPayloadFromLine(line)
  if (!payload || !isProgressPayload(payload)) {
    return false
  }
  progressTracker.handleEvent(JSON.parse(payload))
  return true
}

function createProgressStreamFilter(progressTracker) {
  let pendingPrefix = false

  function handleLine(line) {
    if (pendingPrefix) {
      pendingPrefix = false
      if (tryHandleProgressLine(`${PROGRESS_PREFIX}${line}`, progressTracker)) {
        return true
      }
      line = `${PROGRESS_MARKER}\t${line}`
    }

    if (tryHandleProgressLine(line, progressTracker)) {
      return true
    }

    const trimmed = line.trim()
    if (trimmed === PROGRESS_MARKER || trimmed === '@continuum/progress') {
      pendingPrefix = true
      return true
    }

    if (isProgressStreamLine(line)) {
      return true
    }

    return false
  }

  return {
    handleLine,
    flushPending() {
      pendingPrefix = false
    },
  }
}

function topicSortKey(id) {
  if (id.startsWith('pull:')) return `2:${id}`
  if (id === 'start-stack') return '3:start-stack'
  return `1:${id}`
}

function createProgressTracker({ progressPanel, progressTopics, progressOverall }) {
  const topics = new Map()
  let overallPct = 0
  let spinnerOn = false
  /** @type {{ fill: HTMLElement, pctSpan: HTMLElement, spinner: HTMLElement } | null} */
  let overallElements = null

  function ensureOverallElements() {
    if (overallElements) return overallElements
    if (!progressOverall) return null

    const row = document.createElement('div')
    row.className = 'install-progress-overall-row'

    const labelEl = document.createElement('span')
    labelEl.className = 'install-progress-label font-medium'
    labelEl.textContent = 'Overall'

    const track = document.createElement('div')
    track.className = 'install-progress-track'
    const fill = document.createElement('div')
    fill.className = 'install-progress-fill'
    track.appendChild(fill)

    const tail = document.createElement('span')
    tail.className = 'install-progress-pct flex items-center justify-end gap-1'
    const pctSpan = document.createElement('span')
    const spinner = document.createElement('span')
    spinner.className = 'install-progress-spinner'
    spinner.setAttribute('aria-hidden', 'true')
    spinner.hidden = true

    tail.append(pctSpan, spinner)
    row.append(labelEl, track, tail)
    progressOverall.appendChild(row)

    overallElements = { fill, pctSpan, spinner }
    return overallElements
  }

  function applyTopicList(list, { replace = false } = {}) {
    if (replace) topics.clear()
    for (const t of list ?? []) {
      if (!t?.id) continue
      topics.set(t.id, {
        label: t.label ?? topics.get(t.id)?.label ?? t.id,
        pct: typeof t.pct === 'number' ? t.pct : (topics.get(t.id)?.pct ?? 0),
        state: t.state ?? topics.get(t.id)?.state ?? 'pending',
        weight: t.weight ?? topics.get(t.id)?.weight ?? 1,
      })
    }
  }

  function markAllTopicsDone() {
    for (const t of topics.values()) {
      t.pct = 100
      if (t.state !== 'failed') t.state = 'done'
    }
  }

  function sortedTopicEntries() {
    return [...topics.entries()].sort(([a], [b]) => topicSortKey(a).localeCompare(topicSortKey(b)))
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
    const els = ensureOverallElements()
    if (!els) return

    els.fill.style.width = `${Math.max(0, Math.min(100, overallPct))}%`
    els.fill.classList.toggle('is-active', spinnerOn)
    els.pctSpan.textContent = `${Math.round(overallPct)}%`
    els.spinner.hidden = !spinnerOn
    if (spinnerOn) {
      els.spinner.setAttribute('aria-label', 'Working')
    } else {
      els.spinner.removeAttribute('aria-label')
    }
  }

  function renderAll() {
    if (!progressTopics) return
    progressTopics.replaceChildren()
    for (const [id, t] of sortedTopicEntries()) {
      progressTopics.appendChild(renderRow(id, t.label, t.pct ?? 0, t.state ?? 'pending'))
    }
    renderOverall()
  }

  function showPanel() {
    if (!progressPanel) return
    progressPanel.hidden = false
    progressPanel.classList.remove('hidden')
  }

  function handleEvent(ev) {
    if (!ev || typeof ev !== 'object') return
    switch (ev.type) {
      case 'init':
        applyTopicList(ev.topics, { replace: true })
        showPanel()
        renderAll()
        break
      case 'sync':
        applyTopicList(ev.topics)
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
        showPanel()
        renderOverall()
        break
      case 'finish':
        spinnerOn = false
        if (ev.ok === true) {
          markAllTopicsDone()
          overallPct = 100
        }
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
    overallElements = null
    if (progressTopics) progressTopics.replaceChildren()
    if (progressOverall) progressOverall.replaceChildren()
    if (progressPanel) {
      progressPanel.hidden = true
      progressPanel.classList.add('hidden')
    }
  }

  return { handleEvent, reset }
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

function resolveHostOs(ddClient) {
  const platform = ddClient?.host?.platform ?? ddClient?.desktopUI?.host?.platform
  if (platform === 'win32') return HOST_OS.WINDOWS
  if (platform === 'linux') return HOST_OS.LINUX
  if (platform === 'darwin') return HOST_OS.MACOS
  return null
}

async function detectWindowsHost(cli, ddClient) {
  const hostOs = resolveHostOs(ddClient)
  if (hostOs === HOST_OS.WINDOWS) return true
  if (hostOs === HOST_OS.LINUX || hostOs === HOST_OS.MACOS) return false
  const probe = await execHostSimple(cli, 'cmd', ['/c', 'ver'])
  return probe.ok && probe.result?.code === 0
}

function getEffectiveHostOs(ddClient, hostOsSelect) {
  const detected = resolveHostOs(ddClient)
  if (detected) return detected
  const selected = hostOsSelect?.value?.trim()
  if (selected === HOST_OS.WINDOWS || selected === HOST_OS.LINUX || selected === HOST_OS.MACOS) {
    return selected
  }
  return null
}

function applyHostOsUi({ hostOs, hostOsRow, hostOsSelect, wslDistroRow, installBtn, bootStatus }) {
  if (hostOsRow && hostOsSelect) {
    const showDropdown = hostOs === null
    hostOsRow.hidden = !showDropdown
    if (showDropdown) {
      hostOsRow.classList.remove('hidden')
    } else {
      hostOsRow.classList.add('hidden')
    }
    if (hostOs && hostOsSelect.value !== hostOs) {
      hostOsSelect.value = hostOs
    }
  }

  if (wslDistroRow) {
    const showWsl = hostOs === HOST_OS.WINDOWS
    wslDistroRow.hidden = !showWsl
    if (showWsl) {
      wslDistroRow.classList.remove('hidden')
    } else {
      wslDistroRow.classList.add('hidden')
    }
  }

  if (installBtn) {
    installBtn.disabled = false
  }

  if (bootStatus && hostOs === HOST_OS.MACOS) {
    showStatus(bootStatus, MACOS_READY_STATUS, false)
  }
}

async function execHostSimple(cli, cmd, args) {
  try {
    const result = await cli.exec(cmd, args)
    return { ok: true, result }
  } catch (error) {
    // Some Docker Desktop builds reject the promise on non-zero exit but still attach stdout/stderr/code.
    if (error && typeof error === 'object' && ('code' in error || 'stdout' in error || 'stderr' in error)) {
      return { ok: true, result: error }
    }
    return { ok: false, error }
  }
}

function execExitCode(result) {
  const code = result?.code
  if (code === undefined || code === null) return null
  const numeric = Number(code)
  return Number.isFinite(numeric) ? numeric : null
}

function execSucceeded(result, { expectSubstring } = {}) {
  if (!result) return false
  const out = combinedExecOutput(result)
  const code = execExitCode(result)
  if (expectSubstring && out.includes(expectSubstring)) {
    return code === null || code === 0
  }
  // Some Docker Desktop builds omit code on success; treat as OK when stderr is empty.
  if (code === null) {
    return !/sorry|password is required|a password is required/i.test(out)
  }
  return code === 0
}

function wslHostArgs(distro, tailArgs) {
  return ['-d', distro, ...tailArgs]
}

function formatPasswordlessSudoInstructions(wslDistro, wslUser) {
  return (
    `Passwordless sudo required for Docker Desktop install on Windows.\n\n` +
    `WSL user: ${wslUser}\n` +
    `WSL distro: ${wslDistro}\n\n` +
    `The Docker extension runs the installer as your default WSL user and cannot type your sudo password.\n` +
    `Host automation (/var/lib/mpc-auth-docker), apt packages, and maintenance restart/update all need sudo -n.\n\n` +
    `Configure passwordless sudo from Windows PowerShell:\n\n` +
    `  wsl -d ${wslDistro} -u root\n\n` +
    `Then in the root WSL shell:\n\n` +
    `  visudo\n\n` +
    `Add this line (replace ${wslUser} if your username differs):\n\n` +
    `  ${wslUser} ALL=(ALL) NOPASSWD: ALL\n\n` +
    `Verify as your normal WSL user (exit the root shell first):\n\n` +
    `  wsl -d ${wslDistro}\n` +
    `  sudo -n true && echo OK\n\n` +
    `Then click Install again in the Docker extension.`
  )
}

async function verifyWslPasswordlessSudo(cli, wslDistro, logOutput) {
  appendLog(logOutput, `Checking passwordless sudo for default WSL user in "${wslDistro}"…\n`)

  const userProbe = await execHostSimple(cli, WSL_HOST_WRAPPER, wslHostArgs(wslDistro, ['whoami']))
  const wslUser =
    userProbe.ok && userProbe.result ? combinedExecOutput(userProbe.result).trim() : '<your-wsl-user>'

  const sudoProbe = await execHostSimple(
    cli,
    WSL_HOST_WRAPPER,
    wslHostArgs(wslDistro, ['bash', '-lc', 'command -v sudo >/dev/null && sudo -n true']),
  )

  if (!sudoProbe.ok) {
    appendLog(
      logOutput,
      `[host exec error: ${sudoProbe.error instanceof Error ? sudoProbe.error.message : String(sudoProbe.error)}]\n`,
    )
    appendLog(logOutput, `\n${formatPasswordlessSudoInstructions(wslDistro, wslUser)}\n`)
    return false
  }

  const sudoOut = combinedExecOutput(sudoProbe.result)
  const sudoCode = sudoProbe.result?.code
  appendLog(logOutput, `[exit ${sudoCode ?? 'unknown'}] user=${wslUser}${sudoOut ? ` ${sudoOut}` : ''}\n`)

  if (execSucceeded(sudoProbe.result)) {
    appendLog(logOutput, `Passwordless sudo OK for WSL user "${wslUser}".\n\n`)
    return true
  }

  appendLog(logOutput, `\n${formatPasswordlessSudoInstructions(wslDistro, wslUser)}\n`)
  return false
}

function formatMacPasswordlessSudoInstructions(macUser) {
  return (
    `Passwordless sudo required for Docker Desktop install on macOS.\n\n` +
    `macOS user: ${macUser}\n\n` +
    `The Docker extension runs the installer as your user and cannot type your sudo password.\n` +
    `Host automation (/var/lib/mpc-auth-docker) and VPN (wg-quick) need sudo -n.\n\n` +
    `Configure passwordless sudo in Terminal:\n\n` +
    `  sudo visudo\n\n` +
    `Add a NOPASSWD line for the user shown above. On macOS the default %admin rule requires a password — put your line in /etc/sudoers.d/ (loaded after the main file) or after %admin in visudo:\n\n` +
    `  ${macUser} ALL=(ALL) NOPASSWD: ALL\n\n` +
    `Verify (clears any cached sudo ticket first — Terminal "OK" with a recent sudo password is not enough):\n\n` +
    `  sudo -k\n` +
    `  sudo -n true && echo OK\n\n` +
    `The visudo line must match the macOS user Docker Desktop runs as (shown in the install log).\n\n` +
    `Then click Install again in the Docker extension.`
  )
}

async function verifyMacPasswordlessSudo(cli, logOutput) {
  appendLog(logOutput, 'Checking passwordless sudo on macOS…\n')

  const userProbe = await execHostSimple(cli, MACOS_HOST_WRAPPER, ['/usr/bin/whoami'])
  const macUser =
    userProbe.ok && userProbe.result ? combinedExecOutput(userProbe.result).trim() : '<your-macos-user>'

  if (!userProbe.ok) {
    appendLog(
      logOutput,
      `[host exec error (whoami): ${userProbe.error instanceof Error ? userProbe.error.message : String(userProbe.error)}]\n`,
    )
    appendLog(logOutput, `\n${formatMacPasswordlessSudoInstructions(macUser)}\n`)
    return false
  }

  appendLog(logOutput, `Docker Desktop host exec user: ${macUser}\n`)

  // Host wrapper runs check-passwordless-sudo in a login shell with absolute paths (unlike bare host exec PATH).
  const sudoProbe = await execHostSimple(cli, MACOS_HOST_WRAPPER, ['check-passwordless-sudo'])

  if (!sudoProbe.ok) {
    appendLog(
      logOutput,
      `[host exec error (sudo): ${sudoProbe.error instanceof Error ? sudoProbe.error.message : String(sudoProbe.error)}]\n`,
    )
    appendLog(logOutput, `\n${formatMacPasswordlessSudoInstructions(macUser)}\n`)
    return false
  }

  const sudoOut = combinedExecOutput(sudoProbe.result)
  const sudoCode = execExitCode(sudoProbe.result)
  appendLog(
    logOutput,
    `[exit ${sudoCode ?? sudoProbe.result?.code ?? 'unknown'}] user=${macUser}${sudoOut ? ` ${sudoOut}` : ''}\n`,
  )

  if (execSucceeded(sudoProbe.result)) {
    appendLog(logOutput, `Passwordless sudo OK for macOS user "${macUser}".\n\n`)
    return true
  }

  appendLog(
    logOutput,
    'sudo -n failed in Docker Desktop host exec (Terminal may still work via a cached sudo ticket, sudoers rule order, or a different user).\n',
  )
  appendLog(logOutput, `\n${formatMacPasswordlessSudoInstructions(macUser)}\n`)
  return false
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
function execHostStreaming(cli, cmd, args, logOutput, progressTracker, execOptions = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    let stdoutBuf = ''
    const progressFilter = progressTracker ? createProgressStreamFilter(progressTracker) : null

    const drainStdoutLines = (flushPartial = false) => {
      let nl
      while ((nl = stdoutBuf.indexOf('\n')) !== -1) {
        const line = stdoutBuf.slice(0, nl)
        stdoutBuf = stdoutBuf.slice(nl + 1)
        if (progressFilter?.handleLine(line)) {
          continue
        }
        if (line.length > 0) {
          appendLog(logOutput, `${line}\n`)
        }
      }
      if (flushPartial && stdoutBuf.length > 0) {
        if (progressFilter?.handleLine(stdoutBuf)) {
          stdoutBuf = ''
          return
        }
        appendLog(logOutput, `${stdoutBuf}\n`)
        stdoutBuf = ''
      }
    }

    const drainStderr = (stderr) => {
      if (!stderr) return
      const text = stderr.endsWith('\n') ? stderr : `${stderr}\n`
      for (const line of text.split(/\r?\n/)) {
        if (!line) continue
        if (progressFilter?.handleLine(line)) {
          continue
        }
        appendLog(logOutput, `${line}\n`)
      }
    }

    const finish = (exitCode) => {
      if (settled) return
      settled = true
      drainStdoutLines(true)
      progressFilter?.flushPending()
      appendLog(logOutput, `\n[process exited ${exitCode}]\n`)
      resolve({ code: exitCode })
    }

    const stream = {
      onOutput({ stdout, stderr }) {
        if (stdout) {
          if (progressFilter) {
            stdoutBuf += stdout
            drainStdoutLines(false)
          } else {
            appendLog(logOutput, stdout.endsWith('\n') ? stdout : `${stdout}\n`)
          }
        }
        if (stderr) {
          if (progressFilter) {
            drainStderr(stderr)
          } else {
            appendLog(logOutput, stderr.endsWith('\n') ? stderr : `${stderr}\n`)
          }
        }
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
      cli.exec(cmd, args, { stream, splitOutputLines: true, ...execOptions })
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

function userMessageForPreflightCode(code) {
  switch (code) {
    case PREFLIGHT_EXIT.AV_ACTIVE:
      return (
        'Real-time antivirus protection is active. Turn off Real-time protection for about 30 minutes ' +
        '(Windows Security → Virus & threat protection → Manage settings), then click Install again.'
      )
    case PREFLIGHT_EXIT.NETWORK_FAILED:
      return (
        'GitHub is not reachable from WSL (git probe failed). See the detail log above, fix network or antivirus ' +
        'settings, then click Install again.'
      )
    case PREFLIGHT_EXIT.DOCKER_WSL_FAILED:
      return (
        'docker compose is not available inside WSL. Enable Docker Desktop WSL integration for your distro, ' +
        'restart Docker Desktop, then click Install again.'
      )
    case PREFLIGHT_EXIT.CONFIG_FAILED:
      return (
        'WSL distro not found or misconfigured. Confirm the distro name matches wsl -l -v exactly, then retry.'
      )
    default:
      return `Windows preflight failed (exit ${code}). See the detail log above, then click Install again.`
  }
}

async function runWindowsPreflight(cli, wslDistro, logOutput) {
  appendLog(
    logOutput,
    `Running Windows preflight (antivirus + WSL/GitHub checks) via ${WSL_HOST_WRAPPER}…\n`,
  )

  const probe = await execHostSimple(cli, WSL_HOST_WRAPPER, ['preflight', '-WslDistro', wslDistro])
  if (!probe.ok) {
    appendLog(
      logOutput,
      `[host exec error: ${probe.error instanceof Error ? probe.error.message : String(probe.error)}]\n`,
    )
    return {
      ok: false,
      userMessage: `Could not run Windows preflight via ${WSL_HOST_WRAPPER}. Reinstall the extension, restart Docker Desktop, then retry.`,
    }
  }

  const out = combinedExecOutput(probe.result)
  const code = execExitCode(probe.result)
  appendLog(logOutput, `[exit ${code ?? 'unknown'}]${out ? ` ${out}` : ''}\n`)

  if (code === PREFLIGHT_EXIT.OK || code === null) {
    appendLog(logOutput, 'Windows preflight passed.\n\n')
    return { ok: true }
  }

  return { ok: false, userMessage: userMessageForPreflightCode(code) }
}

function orchestratorEnvVars(skipHostPreflight) {
  const vars = ['CONTINUUM_INSTALL_PROGRESS=json']
  if (skipHostPreflight) {
    vars.unshift('CONTINUUM_SKIP_PREFLIGHT=1')
  }
  return vars
}

async function runInstallOnHost(
  cli,
  { useWsl, wslDistro, profile, scriptArgs, skipHostPreflight = false },
  logOutput,
  progressTracker,
) {
  const orchestrateArgs = ['--profile', profile, ...scriptArgs]

  if (useWsl) {
    appendLog(logOutput, 'Downloading orchestrator script…\n')
    const curlArgs = wslHostArgs(wslDistro, [
      'curl',
      '-fsSL',
      DESKTOP_ORCHESTRATE_SCRIPT_URL,
      '-o',
      ORCHESTRATE_SCRIPT_PATH,
    ])
    const result = await execHostStreaming(cli, WSL_HOST_WRAPPER, curlArgs, logOutput, null)
    if (result.code !== 0) {
      return result
    }
    appendLog(logOutput, `\nRunning orchestrator via ${WSL_HOST_WRAPPER}…\n\n`)
    const runArgs = wslHostArgs(wslDistro, [
      'env',
      ...orchestratorEnvVars(skipHostPreflight),
      'bash',
      ORCHESTRATE_SCRIPT_PATH,
      ...orchestrateArgs,
    ])
    return execHostStreaming(cli, WSL_HOST_WRAPPER, runArgs, logOutput, progressTracker)
  }

  // Linux / macOS: bundled orchestrator via wrapper (rewrites /tmp path; host exec cannot write there — curl exit 23).
  const hostWrapper = profile === 'macos' ? MACOS_HOST_WRAPPER : LINUX_HOST_WRAPPER
  appendLog(logOutput, `Running bundled orchestrator via ${hostWrapper}…\n\n`)
  const runArgs = [
    'env',
    ...orchestratorEnvVars(false),
    'bash',
    ORCHESTRATE_SCRIPT_PATH,
    ...orchestrateArgs,
  ]
  return execHostStreaming(cli, hostWrapper, runArgs, logOutput, progressTracker)
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
  const hostOsRow = document.getElementById('host-os-row')
  const hostOsSelect = document.getElementById('host-os')
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
  let detectedHostOs = resolveHostOs(ddClient)

  if (hostOsSelect && detectedHostOs) {
    hostOsSelect.value = detectedHostOs
  }

  void (async () => {
    wslEnv = await probeWslEnvironment(cli, ddClient)
    const effectiveOs = getEffectiveHostOs(ddClient, hostOsSelect)
    applyHostOsUi({
      hostOs: effectiveOs,
      hostOsRow,
      hostOsSelect,
      wslDistroRow,
      installBtn,
      bootStatus,
    })

    if (effectiveOs === HOST_OS.WINDOWS && wslDistroInput) {
      applyDetectedWslDistro(wslDistroInput, wslEnv)
    }

    if (effectiveOs === HOST_OS.MACOS) {
      showStatus(bootStatus, MACOS_READY_STATUS)
      return
    }

    if (effectiveOs === null) {
      showStatus(
        bootStatus,
        'Select your host OS, then enter keys and public IPv4.',
      )
      return
    }

    if (effectiveOs === HOST_OS.WINDOWS && wslEnv.distros.length > 0) {
      showStatus(
        bootStatus,
        `Ready (${HOST_OS_LABELS[effectiveOs]}) — detected WSL distros: ${wslEnv.distros.join(', ')}. Enter keys and public IPv4, then Install node.`,
      )
      return
    }

    if (effectiveOs === HOST_OS.WINDOWS) {
      showStatus(
        bootStatus,
        'Ready (Windows) — enter the exact WSL distro name from wsl -l -v, keys, and public IPv4.',
      )
      showError(
        resultPanel,
        `Could not list WSL distros via ${WSL_HOST_WRAPPER}. Reinstall the extension so Docker copies the host binary, then quit and restart Docker Desktop.`,
      )
      return
    }

    if (effectiveOs === HOST_OS.LINUX) {
      showStatus(
        bootStatus,
        'Ready (Linux) — install uses sudo for packages, UFW, and systemd. Passwordless sudo recommended. Enter keys and public IPv4.',
      )
      return
    }

    showStatus(bootStatus, 'Ready — enter keys and public IPv4, then Install node.')
  })()

  hostOsSelect?.addEventListener('change', () => {
    const effectiveOs = getEffectiveHostOs(ddClient, hostOsSelect)
    applyHostOsUi({
      hostOs: effectiveOs,
      hostOsRow,
      hostOsSelect,
      wslDistroRow,
      installBtn,
      bootStatus,
    })
    if (effectiveOs === HOST_OS.WINDOWS) {
      applyDetectedWslDistro(wslDistroInput, wslEnv)
    }
    resultPanel.hidden = true
    resultPanel.textContent = ''
    if (effectiveOs === HOST_OS.MACOS) {
      showStatus(bootStatus, MACOS_READY_STATUS)
      return
    }
    if (effectiveOs === null) {
      showStatus(bootStatus, 'Select your host OS, then enter keys and public IPv4.')
      return
    }
    if (effectiveOs === HOST_OS.LINUX) {
      showStatus(
        bootStatus,
        'Ready (Linux) — install uses sudo for packages, UFW, and systemd. Passwordless sudo recommended.',
      )
      return
    }
    showStatus(bootStatus, `Ready (${HOST_OS_LABELS[effectiveOs]}) — enter keys and public IPv4, then Install node.`)
  })

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
    const hostOs = getEffectiveHostOs(ddClient, hostOsSelect)
    applyHostOsUi({
      hostOs,
      hostOsRow,
      hostOsSelect,
      wslDistroRow,
      installBtn,
      bootStatus,
    })

    if (!hostOs) {
      showError(resultPanel, 'Select your host OS (Windows, Linux, or macOS).')
      installBtn.disabled = false
      return
    }

    if (hostOs === HOST_OS.MACOS) {
      const sudoOk = await verifyMacPasswordlessSudo(cli, logOutput)
      if (!sudoOk) {
        showError(
          resultPanel,
          'Passwordless sudo is required on macOS. See the install log for visudo steps, then retry Install.',
        )
        installBtn.disabled = false
        return
      }
    }

    const useWsl = hostOs === HOST_OS.WINDOWS
    const profile =
      hostOs === HOST_OS.LINUX ? 'linux' : hostOs === HOST_OS.MACOS ? 'macos' : 'windows'
    const wslDistro = (wslDistroInput?.value ?? wslEnv.defaultDistro ?? '').trim()
    let skipHostPreflight = false

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

      const sudoOk = await verifyWslPasswordlessSudo(cli, wslDistro, logOutput)
      if (!sudoOk) {
        showError(
          resultPanel,
          `Passwordless sudo is required for WSL user in "${wslDistro}". See the install log for visudo steps, then retry Install.`,
        )
        installBtn.disabled = false
        return
      }

      const preflight = await runWindowsPreflight(cli, wslDistro, logOutput)
      if (!preflight.ok) {
        showError(resultPanel, preflight.userMessage)
        installBtn.disabled = false
        return
      }
      skipHostPreflight = true
    }

    appendLog(
      logOutput,
      useWsl
        ? `Using WSL distro "${wslDistro}" (${HOST_OS_LABELS[hostOs]}) — clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`
        : `Using ${HOST_OS_LABELS[hostOs]} host — clone/install at ${MPC_DESKTOP_REPO_DISPLAY_PATH}, then docker compose up…\n\n`,
    )

    try {
      let result
      if (useWsl) {
        result = await runInstallOnHost(
          cli,
          { useWsl: true, wslDistro, profile, scriptArgs, skipHostPreflight },
          logOutput,
          progressTracker,
        )
      } else {
        result = await runInstallOnHost(
          cli,
          { useWsl: false, wslDistro: null, profile, scriptArgs, skipHostPreflight: false },
          logOutput,
          progressTracker,
        )
      }

      resultPanel.hidden = false
      if (result?.code === 0) {
        if (useWsl && wslDistro) {
          appendLog(logOutput, `\nRegistering Windows logon task for WSL pending-update watcher (${REGISTER_WATCHER_HOST_WRAPPER})…\n`)
          try {
            const reg = await execHostSimple(cli, REGISTER_WATCHER_HOST_WRAPPER, [wslDistro])
            const regOut = combinedExecOutput(reg.result)
            if (regOut) appendLog(logOutput, `${regOut}\n`)
            if (!reg.ok || !execSucceeded(reg.result)) {
              appendLog(
                logOutput,
                `warning: logon task registration failed — run manually in WSL: ~/mpc-config/wsl-desktop/start-watcher.sh\n`,
              )
            }
          } catch (regErr) {
            appendLog(
              logOutput,
              `warning: could not register logon task (${regErr instanceof Error ? regErr.message : String(regErr)}). Start watcher manually: ~/mpc-config/wsl-desktop/start-watcher.sh\n`,
            )
          }
        } else if (hostOs === HOST_OS.MACOS) {
          appendLog(
            logOutput,
            `\nRegistering macOS launchd LaunchAgent for pending-update watcher (${REGISTER_LAUNCHAGENT_HOST_WRAPPER})…\n`,
          )
          try {
            const reg = await execHostSimple(cli, REGISTER_LAUNCHAGENT_HOST_WRAPPER, [])
            const regOut = combinedExecOutput(reg.result)
            if (regOut) appendLog(logOutput, `${regOut}\n`)
            if (!reg.ok || !execSucceeded(reg.result)) {
              appendLog(
                logOutput,
                'warning: LaunchAgent registration failed — run manually: ~/mpc-config/macos-desktop/install-launchagent.sh --repo-dir ~/mpc-config\n',
              )
            }
          } catch (regErr) {
            appendLog(
              logOutput,
              `warning: could not register LaunchAgent (${regErr instanceof Error ? regErr.message : String(regErr)}). Start watcher manually: ~/mpc-config/macos-desktop/start-watcher.sh\n`,
            )
          }
        }
        resultPanel.className = RESULT_PANEL_OK
        const repoHint = useWsl
          ? `<code class="font-mono text-[0.6875rem] text-[var(--text)]">${MPC_DESKTOP_REPO_DISPLAY_PATH}</code> in WSL (${wslDistro})`
          : `<code class="font-mono text-[0.6875rem] text-[var(--text)]">${MPC_DESKTOP_REPO_DISPLAY_PATH}</code> on this machine`
        const watcherNote = useWsl
          ? ' Host restart automation: WSL pending-update watcher (status: <code class="font-mono text-[0.6875rem] text-[var(--text)]">~/mpc-config/wsl-desktop/status-watcher.sh</code> in WSL).'
          : hostOs === HOST_OS.MACOS
            ? ' Host restart automation: macOS pending-update watcher (status: <code class="font-mono text-[0.6875rem] text-[var(--text)]">~/mpc-config/macos-desktop/status-watcher.sh</code>).'
            : hostOs === HOST_OS.LINUX
              ? ' Host restart automation: systemd pending-update.path on this Linux host.'
              : ''
        const backupHint = useWsl
          ? ' under that WSL directory'
          : ' on this machine'
        resultPanel.innerHTML =
          '<p class="m-0"><strong>Install finished.</strong> mpc-config is at ' +
          repoHint +
          '. Stack containers (mongo, mpc-auth, continuum-mcp, continuumdao-node-app) appear in Docker Desktop → Containers. ' +
          'Open continuumdao-node-app at <code class="font-mono text-[0.6875rem] text-[var(--text)]">http://127.0.0.1:3333</code> for Plain HTTP attach. ' +
          'Back up <code class="font-mono text-[0.6875rem] text-[var(--text)]">bootstrap_key/</code>' +
          backupHint +
          ' if a new key was generated.' +
          watcherNote +
          '</p>'
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
