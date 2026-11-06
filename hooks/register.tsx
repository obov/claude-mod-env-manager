import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type {
  CodeFinding, CodeScan, EnvDialog, EnvFile, EnvMode, EnvRow, EnvRowsProps, EnvScan, EnvUi, GitleaksRecord, GitleaksState, HistoryFinding,
} from '../types'
import {
  SKIP_DIRS, baseOf, dirOf, findSecrets, findSecretsInCode, isScannableCode, isTemplateName, isValidKey, lineOf, mask,
  matchesAny, parseEnv, parsePatterns, removeKey, renameKey, setKey, uniqueKey,
} from './env'
import type { Found } from './env'

const PLUGIN = 'env-manager'
const PANE = 'env-manager'
const RENAME_TOOL = `mcp__${PLUGIN}__rename_key`

const scanAtom = atom({ plugin: 'env-manager', key: 'scan' } as const, null, { shape: 'scan-2' })
const uiAtom = atom({ plugin: 'env-manager', key: 'ui' } as const, {
  open: [],
  dirOpen: [],
  dirClosed: [],
  view: 'tree',
  cursor: 'root',
  setCursor: 'set:intercept',
  mode: null,
  message: '',
} as EnvUi, { shape: 'ui-6' })
const codeAtom = atom({ plugin: 'env-manager', key: 'code' } as const, { status: 'idle', files: 0, findings: [], at: 0 } as CodeScan, { shape: 'code-1' })
const gitleaksAtom = atom({ plugin: 'env-manager', key: 'gitleaks' } as const, { version: null, running: false, record: null } as GitleaksState, { shape: 'gl-1' })
const dialogAtom = atom({ plugin: 'env-manager', key: 'dialog' } as const, null as EnvDialog | null, { shape: 'dialog-1' })
const hiddenAtom = atom({ plugin: 'env-manager', key: 'hiddenWarning' } as const, '')

type $ = EngineInterface

const str = (v: unknown, fallback: string) => (typeof v === 'string' && v.trim() !== '' ? v.trim() : fallback)

let cfg = {
  patterns: parsePatterns('.env .env.*'),
  defaultFile: '.env',
  isIntercepting: true,
  maxDepth: 5,
  checkMs: 600_000,
  renamePrompt: '',
  scanFiles: true,
  guardWrites: true,
  gitleaks: 'manual' as 'off' | 'manual' | 'auto',
  raw: {} as Record<string, string>,
}

export const DEFAULT_RENAME_PROMPT =
  "In your reply, in the user's language: 1) tell them which file path and key name each value was stored under, showing only the masked value. 2) Suggest 3-5 key names that fit the context as a numbered list, best first: consider what the user is doing in this prompt and conversation, the provider the value looks like, the names already in {file} ({keys}), and env variable names the project's code reads (process.env.X, os.environ, getenv). Make the current name {stored} the last option. 3) Ask which one to use. When they pick a number or type a name, call {tool} with { file: \"{file}\", from: <current key>, to: <new key> }; if they keep the current name, do nothing."

let lastCheck = 0
let scanning: Promise<EnvScan> | null = null

// ── git ──────────────────────────────────────────────────────────

async function git($: $, root: string, args: string[], stdin?: string) {
  try {
    return await $.process.run(['git', ...args], { cwd: root, timeoutMs: 10_000, ...(stdin === undefined ? {} : { stdin }) })
  } catch {
    return { exitCode: -1, stdout: '', stderr: '' }
  }
}

async function gitInfo($: $, root: string) {
  const top = await git($, root, ['rev-parse', '--show-toplevel'])
  if (top.exitCode !== 0) return null
  const prefix = await git($, root, ['rev-parse', '--show-prefix'])
  return { top: top.stdout.trim(), prefix: prefix.stdout.trim() }
}

/** Paths from a `git ... -z` listing (NUL separated, never quoted). */
function lines(text: string) {
  return new Set(text.split('\0').filter(Boolean))
}

// ── scan ─────────────────────────────────────────────────────────

async function walk($: $, root: string): Promise<{ files: string[]; dirs: string[] }> {
  const found: string[] = []
  const dirs: string[] = []
  const visit = async (rel: string, depth: number) => {
    const entries = await $.fs.list(rel === '' ? root : `${root}/${rel}`).catch(() => [])
    for (const entry of entries) {
      const path = rel === '' ? entry.name : `${rel}/${entry.name}`
      if (entry.kind === 'dir') {
        if (depth < cfg.maxDepth && !SKIP_DIRS.has(entry.name)) {
          dirs.push(path)
          await visit(path, depth + 1)
        }
      } else if (entry.kind === 'file' && matchesAny(entry.name, cfg.patterns)) {
        found.push(path)
      }
    }
  }
  await visit('', 0)
  return { files: found.sort(), dirs: dirs.sort() }
}

async function doScan($: $): Promise<EnvScan> {
  const root = await $.session.cwd()
  const { files: paths, dirs } = await walk($, root)
  const info = await gitInfo($, root)
  let ignored = new Set<string>()
  let tracked = new Set<string>()
  if (info && paths.length > 0) {
    ignored = lines((await git($, root, ['-c', 'core.quotePath=false', 'check-ignore', '-z', '--stdin'], paths.join('\0'))).stdout)
    tracked = lines((await git($, root, ['ls-files', '-z', '--', ...paths])).stdout)
  }
  const files: EnvFile[] = []
  for (const path of paths) {
    const text = await $.fs.read(`${root}/${path}`).catch(() => '')
    files.push({
      path,
      isIgnored: info ? ignored.has(path) : null,
      isTracked: tracked.has(path),
      isTemplate: isTemplateName(baseOf(path)),
      entries: parseEnv(text).map(p => ({ key: p.key, masked: mask(p.value) })),
    })
  }
  const scan: EnvScan = { root, gitRoot: info?.top ?? null, files, dirs, scannedAt: await $.clock.now() }
  await update($, scanAtom, () => scan)
  lastCheck = scan.scannedAt
  return scan
}

function rescan($: $): Promise<EnvScan> {
  if (!scanning) scanning = doScan($).finally(() => { scanning = null })
  return scanning
}

const issuesOf = (scan: EnvScan | null) =>
  (scan?.files ?? []).filter(f => !f.isTemplate && (f.isIgnored === false || f.isTracked))

const signature = (scan: EnvScan | null) =>
  issuesOf(scan).map(f => `${f.path}:${f.isIgnored}:${f.isTracked}`).join('|')

const warnText = (scan: EnvScan | null) => {
  const issues = issuesOf(scan)
  const unignored = issues.filter(f => f.isIgnored === false).length
  const tracked = issues.filter(f => f.isTracked).length
  const parts: string[] = []
  if (unignored) parts.push(`gitignore 미등록 ${unignored}개`)
  if (tracked) parts.push(`git 추적 중 ${tracked}개`)
  return parts.join(', ')
}

// ── file operations ──────────────────────────────────────────────

const abs = (root: string, rel: string) => `${root}/${rel.replace(/^\.\//, '')}`

function readText($: $, path: string): Promise<string> {
  return $.fs.read(path).catch(() => '')
}

/** Adds `rel` to the repo's root .gitignore when git does not ignore it yet. */
async function ensureIgnored($: $, root: string, rel: string): Promise<string> {
  const info = await gitInfo($, root)
  if (!info) return 'git 저장소 아님'
  const check = await git($, root, ['check-ignore', '-q', '--', rel])
  if (check.exitCode === 0) return '이미 gitignore 등록됨'
  const gitignore = `${info.top}/.gitignore`
  const before = await readText($, gitignore)
  const entry = `/${info.prefix}${rel}`
  const sep = before === '' || before.endsWith('\n') ? '' : '\n'
  await $.fs.write(gitignore, `${before}${sep}${entry}\n`)
  return `.gitignore에 ${entry} 추가`
}

async function setValue($: $, root: string, rel: string, key: string, value: string) {
  const path = abs(root, rel)
  await $.fs.write(path, setKey(await readText($, path), key, value))
}

const CLOSED = { mode: null } as const

/** Shows a message and closes any open input. */
function say($: $, message: string) {
  return update($, uiAtom, ui => ({ ...ui, ...CLOSED, message }))
}

/** Shows a message and keeps the open input (a rejected submit). */
function hint($: $, message: string) {
  return update($, uiAtom, ui => ({ ...ui, message }))
}

const toggle = (list: string[], item: string) =>
  list.includes(item) ? list.filter(x => x !== item) : [...list, item]


/** Replaces {name} placeholders; unknown ones stay as written. */
export function fillPrompt(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (all, name: string) => values[name] ?? all)
}

export const register: Register = (on, options) => {
  cfg = {
    patterns: parsePatterns(str(options.patterns, '.env .env.*')),
    defaultFile: str(options.defaultFile, '.env').replace(/^\.\//, ''),
    isIntercepting: str(options.intercept, 'on') === 'on',
    maxDepth: Math.max(0, Number(str(options.maxDepth, '5')) || 5),
    checkMs: Math.max(1, Number(str(options.checkMinutes, '10')) || 10) * 60_000,
    renamePrompt: str(options.renamePrompt, DEFAULT_RENAME_PROMPT),
    scanFiles: str(options.scanFiles, 'on') === 'on',
    guardWrites: str(options.guardWrites, 'on') === 'on',
    gitleaks: (['off', 'manual', 'auto'] as const).find(x => x === str(options.gitleaks, 'manual')) ?? 'manual',
    raw: Object.fromEntries(SETTINGS.map(f => [f.field, str(options[f.field], f.fallback)])),
  }
  const { patterns, defaultFile, isIntercepting, checkMs } = cfg

  // ── session ──────────────────────────────────────────────────────

  on('session.start', async ($, e, next) => {
    const started = await next(e)
    await $.command.register({ name: 'env', description: 'env 파일 트리 열기 (/env scan: 재검사)' })
    await $.tool.register({
      name: 'rename_key',
      description:
        'Rename a key in a local env file managed by env-manager, without reading or printing its value. ' +
        'Use after the user picks a new name for a secret env-manager stored.',
      inputSchema: {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'env file path, relative to the working directory or absolute' },
          from: { type: 'string', description: 'current key name' },
          to: { type: 'string', description: 'new key name ([A-Za-z_][A-Za-z0-9_]*)' },
        },
        required: ['file', 'from', 'to'],
      },
      isDeferred: false,
    })
    const scan = await rescan($)
    const warn = warnText(scan)
    if (warn) $.ui.toast(`env 유출 위험: ${warn} (/env)`, { timeoutMs: 8000 })
    if (cfg.scanFiles) void scanCode($, scan).catch(() => undefined)
    await prepareGitleaks($, scan).catch(() => undefined)
    return started
  })

  on('command.run', { command: 'env' }, async ($, e) => {
    if (e.args.trim() === 'scan') {
      const scan = await rescan($)
      const warn = warnText(scan)
      const list = scan.files.map(f => `  ${f.path}  (${f.entries.length} keys, ${f.isTemplate ? '템플릿' : f.isTracked ? 'git 추적 중' : f.isIgnored === false ? 'gitignore 미등록' : f.isIgnored ? 'ignored' : 'git 없음'})`)
      const code = cfg.scanFiles ? await scanCode($, scan) : null
      const codeLines = (code?.findings ?? []).map(f => `  ${f.path}:${f.line}  ${f.rule}  ${f.masked}`)
      const gl = await read($, gitleaksAtom)
      const hist = gl.record ? [`커밋 기록(gitleaks): ${gl.record.count}건 · ${new Date(gl.record.ranAt).toISOString().slice(0, 16).replace('T', ' ')}`] : []
      return {
        text: [
          `env 파일 ${scan.files.length}개${warn ? ` · 위험: ${warn}` : ' · 위험 없음'}`,
          ...list,
          ...(code ? [`하드코드 시크릿 ${code.findings.length}건 (파일 ${code.files}개 검사)`, ...codeLines] : []),
          ...hist,
        ].join('\n'),
      }
    }
    void rescan($).catch(() => undefined)
    await openPane($)
    return { text: 'env 패널 열림' }
  })

  // ── leak checks ──────────────────────────────────────────────────

  on('turn.complete', async ($, e, next) => {
    const done = await next(e)
    const now = await $.clock.now()
    if (now - lastCheck >= checkMs) {
      const before = signature(await read($, scanAtom))
      const scan = await rescan($)
      const after = signature(scan)
      if (after && after !== before) $.ui.toast(`env 유출 위험: ${warnText(scan)} (/env)`, { timeoutMs: 8000 })
      if (cfg.scanFiles) {
        const was = (await read($, codeAtom)).findings.length
        const code = await scanCode($, scan)
        if (code.findings.length > was) $.ui.toast(`하드코드 시크릿 ${code.findings.length}건 (/env)`, { timeoutMs: 8000 })
      }
    }
    return done
  })

  const READERS = /\b(cat|less|more|head|tail|bat|grep|rg|awk|sed|source|xxd|strings|cp|scp|curl)\b/

  const touchesEnv = (text: string) =>
    text.split(/[\s'"`;|&<>()=]+/).some(word => word !== '' && matchesAny(baseOf(word), patterns) && !isTemplateName(baseOf(word)))

  on('tool.call', async ($, e, next) => {
    const tool = String(e.tool)
    const input = e as unknown as Record<string, unknown>
    const filePath = typeof input.file_path === 'string' ? input.file_path : ''
    const command = typeof input.command === 'string' ? input.command : ''

    const isFileTool = filePath !== '' && touchesEnv(filePath)
    const isBashEnv = tool === 'Bash' && touchesEnv(command)

    if ((tool === 'Read' && isFileTool) || (isBashEnv && READERS.test(command))) {
      $.ui.toast(`Claude가 env 파일 내용을 읽는 중: 비밀값이 모델로 전송될 수 있음`, { timeoutMs: 8000 })
    }

    if (cfg.guardWrites && (tool === 'Write' || tool === 'Edit') && filePath !== '' && !matchesAny(baseOf(filePath), patterns)) {
      const written = typeof input.content === 'string' ? input.content : typeof input.new_string === 'string' ? input.new_string : ''
      const secrets = written === '' ? [] : findSecretsInCode(written)
      if (secrets.length > 0) {
        const root = await $.session.cwd()
        const saved = await storeSecrets($, root, defaultFile, secrets)
        const list = [...saved.stored.entries()].map(([value, x]) => `${x.key} (${mask(value)})`).join(', ')
        $.ui.toast(`코드에 키를 쓰려는 것을 막음 → ${defaultFile}에 저장: ${[...saved.stored.values()].map(x => x.key).join(', ')}`, { timeoutMs: 8000 })
        void rescan($).catch(() => undefined)
        return {
          deny:
            `env-manager blocked this ${tool}: it would hardcode ${saved.stored.size} secret(s) in ${filePath}. ` +
            `They are now stored in ${saved.path} as ${list} (gitignore: ${saved.ignoreNote}). ` +
            `Rewrite the code to read them from the environment (process.env.KEY, os.environ["KEY"], os.Getenv("KEY"), ...) and write again; never put the value in source. ` +
            `Tell the user in their language that the key was moved to ${defaultFile}.`,
        }
      }
    }

    const ran = await next(e)
    if (cfg.scanFiles && (tool === 'Write' || tool === 'Edit') && filePath !== '') void rescanCodeFile($, filePath).catch(() => undefined)

    const touchesIgnore = /\.gitignore\b/.test(filePath) || /\.gitignore\b|\bgit\s+(add|rm|mv|commit)\b/.test(command)
    if ((tool === 'Write' || tool === 'Edit') && (isFileTool || touchesIgnore)) void rescan($).catch(() => undefined)
    else if (tool === 'Bash' && (isBashEnv || touchesIgnore)) void rescan($).catch(() => undefined)
    return ran
  })

  // ── secrets typed into a prompt ──────────────────────────────────

  on('prompt.submit', async ($, e, next) => {
    const kind = (e.origin as { kind?: string } | undefined)?.kind
    const isTyped = kind === undefined || kind === 'composer' || kind === 'bridge' || kind === 'sdk'
    if (!isIntercepting || e.command || e.isMeta || !isTyped) return next(e)
    const secrets = findSecrets(e.text)
    if (secrets.length === 0) return next(e)

    const root = await $.session.cwd()
    const { path, keys, stored, ignoreNote } = await storeSecrets($, root, defaultFile, secrets)

    let prompt = e.text
    for (const s of [...secrets].reverse()) {
      const key = stored.get(s.value)?.key ?? s.key
      prompt = prompt.slice(0, s.start) + `[env:${defaultFile}#${key}]` + prompt.slice(s.end)
    }

    const list = [...stored.entries()]
      .map(([value, s]) => `- ${s.key} = ${mask(value)} (detected as ${s.detected}${s.isNew ? '' : ', already stored under this key'})`)
      .join('\n')

    const context = [
      `[env-manager] The user's prompt contained ${stored.size} secret value(s). Before you saw the prompt, env-manager removed them and saved them to the env file ${path}:`,
      list,
      `gitignore: ${ignoreNote}.`,
      `Each placeholder [env:${defaultFile}#KEY] in the prompt stands for the value stored under KEY. Never ask the user to paste the secret again, never read, print or log the env file's values; code should read the value from the environment (e.g. process.env.KEY).`,
      fillPrompt(cfg.renamePrompt, {
        file: defaultFile,
        path,
        stored: [...stored.values()].map(s => s.key).join(', '),
        keys: [...keys].filter(k => ![...stored.values()].some(s => s.key === k)).join(', ') || 'none',
        tool: RENAME_TOOL,
      }),
    ].join('\n')

    $.ui.toast(`비밀값 ${stored.size}개 → ${defaultFile} 저장 (${[...stored.values()].map(s => s.key).join(', ')})`, { timeoutMs: 6000 })
    void rescan($).catch(() => undefined)
    return next({ ...e, text: prompt, context: [...(e.context ?? []), context] })
  }).catch(($, e, next) =>
    next.called ? next(e) : { drop: 'env-manager: 프롬프트의 비밀값을 env 파일에 저장하지 못해 전송 중단. 비밀값을 지우고 다시 입력 필요' },
  )

  on('tool.call', { tool: 'mcp__env-manager__rename_key' }, async ($, e) => {
    const input = e as unknown as Record<string, unknown>
    const file = typeof input.file === 'string' ? input.file : defaultFile
    const from = typeof input.from === 'string' ? input.from : ''
    const to = typeof input.to === 'string' ? input.to : ''
    if (!isValidKey(to)) return { result: `Invalid key name "${to}": use letters, digits and _ and do not start with a digit.` }
    const root = await $.session.cwd()
    const path = file.startsWith('/') ? file : abs(root, file)
    const text = await readText($, path)
    const keys = parseEnv(text).map(p => p.key)
    if (!keys.includes(from)) return { result: `Key "${from}" not found in ${path}. Keys: ${keys.join(', ') || '(none)'}` }
    if (keys.includes(to)) return { result: `Key "${to}" already exists in ${path}; pick another name.` }
    await $.fs.write(path, renameKey(text, from, to))
    void rescan($).catch(() => undefined)
    $.ui.toast(`${file}: ${from} → ${to}`)
    return { result: `Renamed ${from} to ${to} in ${path}. The value is unchanged.` }
  })

  // ── band above the prompt ────────────────────────────────────────

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const scan = await read($, scanAtom)
    const code = await read($, codeAtom)
    const gl = await read($, gitleaksAtom)
    const sig = [signature(scan), ...code.findings.map(f => `${f.path}:${f.line}`), gl.record?.count ? `h${gl.record.head}:${gl.record.count}` : ''].filter(Boolean).join('|')
    if (e.props.hasSurvey || !sig || sig === (await read($, hiddenAtom))) return next(e)
    const { Box, Button, Text } = $.ui.resolve(e)
    const parts = [warnText(scan), code.findings.length ? `하드코드 시크릿 ${code.findings.length}건` : '', gl.record?.count ? `커밋 기록 ${gl.record.count}건` : ''].filter(Boolean)
    return (
      <Box flexDirection="row" gap={1}>
        <Text color="warning">⚠ env 유출 위험: {parts.join(', ')}</Text>
        <Button key="env-open" label="열기" onPress={() => void openPane($)} />
        <Button key="env-hide" label="숨기기" dimColor onPress={() => update($, hiddenAtom, () => sig)} />
      </Box>
    )
  })

  // ── pane ─────────────────────────────────────────────────────────

  on('ui.message', async ($, e, next) => {
    if (e.requestId !== PANE || e.element !== 'rows' || !e.data || typeof e.data !== 'object') return next(e)
    const data = e.data as { key?: unknown; press?: unknown }
    const scan = await read($, scanAtom)
    if (!scan) return {}
    const ui = await read($, uiAtom)
    const isSettings = ui.view === 'settings'
    const rows = isSettings ? buildSettingsRows(await read($, gitleaksAtom)) : buildRows(scan, ui, await read($, codeAtom), await read($, gitleaksAtom)).rows
    const ids = rows.map(r => r.id)
    const current = isSettings ? ui.setCursor : ui.cursor
    const cursor = ids.includes(current) ? current : (ids[0] ?? 'root')
    const setCursor = (id: string) => update($, uiAtom, u => (isSettings ? { ...u, setCursor: id } : { ...u, cursor: id }))
    const run = (id: string, key: string) => (isSettings ? actSetting($, scan, id, key) : act($, scan, ui, id, key, e.surface))

    if (typeof data.press === 'string') {
      if (await read($, dialogAtom)) return {}
      if (data.press === cursor) await run(cursor, 'return')
      else await setCursor(String(data.press))
      return {}
    }
    if (typeof data.key !== 'string') return {}
    if (await read($, dialogAtom)) {
      if (data.key === 'escape') await closeDialog($, '')
      return {}
    }
    const key = HANGUL_KEYS[data.key] ?? data.key
    if (key === 's') {
      await update($, uiAtom, (u): EnvUi => ({ ...u, view: u.view === 'settings' ? 'tree' : 'settings', mode: null, message: '' }))
      return {}
    }
    const at = ids.indexOf(cursor)
    const move = (to: number) => setCursor(ids[Math.max(0, Math.min(ids.length - 1, to))] ?? cursor)
    if (key === 'up' || key === 'k') await move(at - 1)
    else if (key === 'down' || key === 'j') await move(at + 1)
    else if (key === 'home' || key === 'g') await move(0)
    else if (key === 'end' || key === 'G') await move(ids.length - 1)
    else await run(cursor, key)
    return {}
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const elements = $.ui.resolve(e)
    const { Box, Button, Text, Input } = elements
    const Client = 'Client' in elements ? elements.Client : undefined
    const scan = await read($, scanAtom)
    const ui = await read($, uiAtom)

    if (!scan) {
      return (
        <Box flexDirection="column">
          <Text dimColor>아직 검사 전</Text>
          <Button key="rescan" plain label="r 검사" onPress={() => void rescan($).catch(() => undefined)} />
        </Box>
      )
    }

    const code = await read($, codeAtom)
    const gl = await read($, gitleaksAtom)
    const isSettings = ui.view === 'settings'
    const rows = isSettings ? buildSettingsRows(gl) : buildRows(scan, ui, code, gl).rows
    const current = isSettings ? ui.setCursor : ui.cursor
    const cursor = rows.some(r => r.id === current) ? current : (rows[0]?.id ?? 'root')
    const issues = issuesOf(scan).length + code.findings.length + (gl.record?.count ?? 0)
    const props: EnvRowsProps = { rows, active: cursor, activeBg: 'ansi256(238)', hoverBg: 'ansi256(236)' }
    const hints = isSettings ? settingsHints(cursor) : hintsFor(cursor, scan)
    const runAct = (id: string, key: string, surface: Parameters<$['ui']['copy']>[0]['surface']) =>
      isSettings ? actSetting($, scan, id, key) : act($, scan, ui, id, key, surface)
    const tab = (id: 'tree' | 'settings', label: string) => (
      <Button
        key={`tab:${id}`}
        plain
        dimColor={ui.view !== id}
        label={label}
        onPress={() => void update($, uiAtom, u => ({ ...u, view: id, mode: null, message: '' }))}
      />
    )

    const header = (
      <Box key="header" flexDirection="row" gap={2}>
        {tab('tree', '▤ 트리')}
        {tab('settings', '⚙ 설정')}
        <Box flexGrow={1} />
        {issues > 0 ? <Text color="warning">⚠ 유출 위험 {issues}</Text> : scan.files.length > 0 ? <Text color="success">✓ 안전</Text> : null}
        {code.status === 'running' && <Text dimColor>코드 검사 중…</Text>}
        {gl.running && <Text dimColor>gitleaks 실행 중…</Text>}
      </Box>
    )

    const dialog = await read($, dialogAtom)
    const card = dialog ? dialogCard(dialog) : null
    function dialogCard(d: EnvDialog) {
      const patch = (p: Partial<EnvDialog>) => update($, dialogAtom, x => (x ? ({ ...x, ...p, error: '' } as EnvDialog) : x))
      const submit = () => void submitDialog($, scan!)
      const field = (k: 'name' | 'key' | 'value', label: string, placeholder: string, value: string) => (
        <Input
          key={`dlg-${k}`}
          label={label}
          placeholder={placeholder}
          value={value}
          submitLabel="확인"
          onInput={v => void patch({ [k]: v })}
          onSubmit={v => void patch({ [k]: v }).then(submit)}
        />
      )
      const rel = d.kind === 'new' ? newTarget(d) : d.file
      const path = abs(scan!.root, rel)
      const where = (atRoot: boolean, label: string) => (
        <Button
          key={atRoot ? 'dlg-root' : 'dlg-dir'}
          plain
          dimColor={d.kind === 'new' && d.atRoot !== atRoot}
          label={`${d.kind === 'new' && d.atRoot === atRoot ? '◉' : '○'} ${label}`}
          onPress={() => void patch({ atRoot })}
        />
      )
      const isNew = d.kind === 'new'
      return (
        <Box key="dlg-card" position="absolute" top={0} left={2} right={2} flexDirection="column" borderStyle="round" borderColor="suggestion" backgroundColor="ansi256(235)" paddingX={1}>
          <Text bold color="suggestion">{isNew ? '새 env 파일' : '키 추가'}</Text>
          {d.kind === 'new' && d.dir !== '' ? (
            <Box key="dlg-where" flexDirection="row" gap={2}>
              <Text dimColor>위치</Text>
              {where(false, `선택 폴더 ${d.dir}/`)}
              {where(true, '루트')}
            </Box>
          ) : null}
          {d.kind === 'new' ? field('name', '파일 이름 ', '.env', d.name) : null}
          <Box flexDirection="row" gap={1}>
            <Text dimColor>{isNew ? '생성 경로' : '대상 파일'}</Text>
            <Text bold>{path}</Text>
          </Box>
          {isNew ? (
            <Text dimColor>
              {isTemplateName(baseOf(rel)) ? '템플릿: gitignore 등록 안 함' : 'gitignore 자동 등록'}
              {matchesAny(baseOf(rel), cfg.patterns) ? '' : ' · 추적 패턴 미일치로 트리에 안 보임'}
            </Text>
          ) : null}
          {field('key', isNew ? 'KEY(선택) ' : 'KEY ', 'API_KEY  (KEY=값 붙여넣기 가능)', d.key)}
          {field('value', '값 ', '비워 두면 빈 값', d.value)}
          {d.error ? <Text color="error">{d.error}</Text> : null}
          <Box key="dlg-actions" flexDirection="row" gap={2}>
            <Button key="dlg-ok" label={isNew ? '생성' : '저장'} onPress={submit} />
            <Button key="dlg-cancel" label="취소" dimColor onPress={() => void closeDialog($, '')} />
          </Box>
        </Box>
      )
    }

    const footer = ui.mode ? (
      <Box key="footer" flexDirection="row" gap={1}>
        <Input
          key={`mode-input:${modeId(ui.mode)}`}
          label={modeLabel(ui.mode)}
          placeholder={modePlaceholder(ui.mode)}
          value={ui.mode.kind === 'setting' ? (cfg.raw[ui.mode.field] ?? '') : undefined}
          submitLabel=" "
          autoFocus
          onSubmit={value => void submitMode($, scan, ui.mode, value)}
        />
        <Button key="cancel-input" plain label="✖" dimColor onPress={() => void closeMode($, '')} />
      </Box>
    ) : (
      <Box key="footer" flexDirection="row" flexWrap="wrap" columnGap={2}>
        {hints.map(item => (
          <Button
            key={`hint:${item.key}`}
            plain
            dimColor
            label={`${item.key} ${item.label}`}
            onPress={press => void runAct(cursor, item.key, press.surface)}
          />
        ))}
      </Box>
    )

    return (
      <Box flexDirection="column">
        {header}
        <Box key="body" flexDirection="column" minHeight={card ? (dialog?.kind === 'new' ? 12 : 8) : 0}>
        {Client ? (
          <Client key="rows" module="./rows.tsx" props={props} />
        ) : (
          <Box key="rows" flexDirection="column">
            {rows.map(r => (
              <Button key={r.id} plain label={[...r.left, ...r.right].map(x => x.t).join(' ')} onPress={press => void runAct(r.id, 'return', press.surface)} />
            ))}
          </Box>
        )}
        {card}
        </Box>
        {!isSettings && scan.files.length === 0 && <Text dimColor>env 파일 없음 · n 으로 생성</Text>}
        <Text dimColor>{ui.message || ' '}</Text>
        {card ? <Text dimColor>Tab 칸 이동 · Enter 확인</Text> : footer}
      </Box>
    )
  })
}

// Korean (두벌식) layout: the jamo a key types while the IME is in Hangul mode → the Latin key.
const HANGUL_KEYS: Record<string, string> = {
  ㅂ: 'q', ㅈ: 'w', ㄷ: 'e', ㄱ: 'r', ㅅ: 't', ㅛ: 'y', ㅕ: 'u', ㅑ: 'i', ㅐ: 'o', ㅔ: 'p',
  ㅁ: 'a', ㄴ: 's', ㅇ: 'd', ㄹ: 'f', ㅎ: 'g', ㅗ: 'h', ㅓ: 'j', ㅏ: 'k', ㅣ: 'l',
  ㅋ: 'z', ㅌ: 'x', ㅊ: 'c', ㅍ: 'v', ㅠ: 'b', ㅜ: 'n', ㅡ: 'm',
}

// ── pane model ─────────────────────────────────────────────────────

type View = { rows: EnvRow[] }

const FILE_STATUS = (f: EnvFile): { t: string; c: string } =>
  f.isTemplate ? { t: '템플릿', c: '' }
    : f.isTracked ? { t: '✗ git 추적', c: 'error' }
      : f.isIgnored === false ? { t: '✗ 미등록', c: 'warning' }
        : f.isIgnored ? { t: '✓ ignored', c: 'success' }
          : { t: 'git 없음', c: '' }

function isDirOpen(scan: EnvScan, ui: EnvUi, dir: string): boolean {
  if (ui.dirOpen.includes(dir)) return true
  if (ui.dirClosed.includes(dir)) return false
  return dir === '' || scan.files.some(f => f.path.startsWith(`${dir}/`))
}

function buildRows(scan: EnvScan, ui: EnvUi, code?: CodeScan, gl?: GitleaksState): View {
  const rows: EnvRow[] = []
  const childDirs = new Map<string, string[]>()
  for (const d of scan.dirs) childDirs.set(dirOf(d), [...(childDirs.get(dirOf(d)) ?? []), d])
  const childFiles = new Map<string, EnvFile[]>()
  for (const f of scan.files) childFiles.set(dirOf(f.path), [...(childFiles.get(dirOf(f.path)) ?? []), f])
  const envBelow = (dir: string) => scan.files.filter(f => f.path.startsWith(`${dir}/`)).length

  rows.push({ id: 'root', left: [{ t: '▾ ', dim: true }, { t: `${baseOf(scan.root) || scan.root}/`, b: true }], right: [] })

  const walk = (dir: string, depth: number) => {
    const pad = '  '.repeat(depth)
    for (const sub of childDirs.get(dir) ?? []) {
      const open = isDirOpen(scan, ui, sub)
      const below = envBelow(sub)
      rows.push({
        id: `d:${sub}`,
        left: [{ t: `${pad}${open ? '▾' : '▸'} `, dim: true }, { t: `${baseOf(sub)}/`, c: below > 0 ? 'suggestion' : '', dim: below === 0 }],
        right: below > 0 ? [{ t: `${below} env`, dim: true }] : [],
      })
      if (open) walk(sub, depth + 1)
    }
    for (const f of childFiles.get(dir) ?? []) {
      const open = ui.open.includes(f.path)
      const st = FILE_STATUS(f)
      rows.push({
        id: `f:${f.path}`,
        left: [{ t: `${pad}${open ? '▾' : '▸'} `, dim: true }, { t: baseOf(f.path), c: st.c === 'error' || st.c === 'warning' ? st.c : '', b: true }],
        right: [{ t: `${f.entries.length} ${f.entries.length === 1 ? 'key' : 'keys'}  `, dim: true }, { t: st.t, c: st.c, dim: st.c === '' }],
      })
      if (!open) continue
      for (const entry of f.entries) {
        rows.push({
          id: `k:${f.path}\u0000${entry.key}`,
          left: [{ t: `${pad}    ` }, { t: entry.key }],
          right: [{ t: entry.masked, dim: true }],
        })
      }
      if (f.entries.length === 0) rows.push({ id: `e:${f.path}`, left: [{ t: `${pad}    ` }, { t: '(비어 있음 · a 로 키 추가)', dim: true }], right: [] })
    }
  }
  walk('', 1)

  const findings = code?.findings ?? []
  if (findings.length > 0) {
    const open = ui.open.includes('#code')
    rows.push({ id: 'code', left: [{ t: `${open ? '▾' : '▸'} `, dim: true }, { t: '⚠ 하드코드 시크릿', c: 'warning', b: true }], right: [{ t: `${findings.length}건`, c: 'warning' }] })
    if (open) {
      findings.forEach((f, i) => rows.push({
        id: `cf:${i}`,
        left: [{ t: '    ' }, { t: `${f.path}:${f.line}` }],
        right: [{ t: `${f.rule}  `, dim: true }, { t: f.masked, dim: true }],
      }))
    }
  }
  const hist = gl?.record?.findings ?? []
  if ((gl?.record?.count ?? 0) > 0) {
    const open = ui.open.includes('#hist')
    rows.push({ id: 'hist', left: [{ t: `${open ? '▾' : '▸'} `, dim: true }, { t: '⚠ 커밋 기록 속 키', c: 'error', b: true }], right: [{ t: `${gl?.record?.count ?? 0}건`, c: 'error' }] })
    if (open) {
      hist.forEach((f, i) => rows.push({
        id: `hf:${i}`,
        left: [{ t: '    ' }, { t: `${f.file}:${f.line}` }],
        right: [{ t: `${f.rule}  `, dim: true }, { t: f.commit.slice(0, 7), dim: true }],
      }))
    }
  }
  return { rows }
}

type Target =
  | { kind: 'root' }
  | { kind: 'dir'; dir: string }
  | { kind: 'file'; file: EnvFile }
  | { kind: 'key'; file: EnvFile; key: string }

function targetOf(scan: EnvScan, id: string): Target {
  if (id.startsWith('d:')) return { kind: 'dir', dir: id.slice(2) }
  const fileOf = (path: string) => scan.files.find(f => f.path === path)
  if (id.startsWith('f:') || id.startsWith('e:')) {
    const file = fileOf(id.slice(2))
    if (file) return { kind: 'file', file }
  }
  if (id.startsWith('k:')) {
    const [path = '', key = ''] = id.slice(2).split('\u0000')
    const file = fileOf(path)
    if (file) return { kind: 'key', file, key }
  }
  return { kind: 'root' }
}

type Hint = { key: string; label: string }

function hintsFor(cursor: string, scan: EnvScan): Hint[] {
  const t = targetOf(scan, cursor)
  const nav: Hint[] = [{ key: '↑↓', label: '이동' }]
  if (cursor === 'code' || cursor === 'hist') return [...nav, { key: '⏎', label: '열기' }, { key: 's', label: '설정' }]
  if (cursor.startsWith('cf:') || cursor.startsWith('hf:')) return [...nav, { key: 'c', label: '위치 복사' }]
  if (t.kind === 'root') return [...nav, { key: 'n', label: '새 env' }, { key: 'r', label: '재검사' }, { key: 's', label: '설정' }]
  if (t.kind === 'dir') return [...nav, { key: '⏎', label: '열기' }, { key: 'n', label: '새 env' }, { key: 'r', label: '재검사' }]
  const file = t.file
  const fileHints: Hint[] = [{ key: 'a', label: '키 추가' }, { key: 'd', label: '복제' }]
  if (!file.isTemplate && file.isIgnored === false) fileHints.push({ key: 'i', label: 'gitignore' })
  if (!file.isTemplate && file.isTracked) fileHints.push({ key: 'u', label: '추적 해제' })
  if (t.kind === 'file') return [...nav, { key: '⏎', label: '열기' }, ...fileHints]
  return [...nav, { key: 'c', label: '값 복사' }, { key: 'e', label: '수정' }, { key: 'x', label: '삭제' }, { key: 'a', label: '키 추가' }]
}

function modeId(mode: EnvMode): string {
  if (mode.kind === 'setting') return `setting:${mode.field}`
  return mode.kind === 'edit' ? `edit:${mode.file}:${mode.key}` : `${mode.kind}:${mode.file}`
}

function modeLabel(mode: EnvMode): string {
  if (mode.kind === 'setting') return SETTINGS.find(f => f.field === mode.field)?.label ?? mode.field
  if (mode.kind === 'edit') return `${mode.key} 새 값`
  return `복제 · ${mode.file} →`
}

function modePlaceholder(mode: EnvMode): string {
  if (mode.kind === 'setting') return SETTINGS.find(f => f.field === mode.field)?.fallback ?? ''
  if (mode.kind === 'edit') return '새 값'
  return '.env.local'
}

async function openPane($: $): Promise<void> {
  await $.ui.open({ id: PANE, title: 'env-manager', focus: true })
  await $.ui.focus({ requestId: PANE, key: 'rows' }).catch(() => undefined)
}

async function closeMode($: $, message: string): Promise<void> {
  await update($, uiAtom, u => ({ ...u, mode: null, message }))
  await $.ui.focus({ requestId: PANE, key: 'rows' }).catch(() => undefined)
}

async function act($: $, scan: EnvScan, ui: EnvUi, cursor: string, key: string, surface: Parameters<$['ui']['copy']>[0]['surface']): Promise<void> {
  const { root } = scan
  const t = targetOf(scan, cursor)
  const setMode = (mode: EnvMode) => update($, uiAtom, u => ({ ...u, mode, message: '' }))
  const dirOfTarget = t.kind === 'dir' ? t.dir : t.kind === 'file' || t.kind === 'key' ? dirOf(t.file.path) : ''

  if (key === 'r') {
    const fresh = await rescan($)
    if (cfg.scanFiles) await scanCode($, fresh)
    await say($, '재검사 완료')
    return
  }
  if (key === 'n') return void (await openDialog($, { kind: 'new', dir: dirOfTarget, atRoot: false, name: '', key: '', value: '', error: '' }))

  if (cursor === 'code' || cursor === 'hist') {
    if (key === 'return' || key === '⏎' || key === ' ' || key === 'right' || key === 'left' || key === 'l' || key === 'h') {
      const id = `#${cursor}`
      const open = ui.open.includes(id)
      if ((open && (key === 'right' || key === 'l')) || (!open && (key === 'left' || key === 'h'))) return
      await update($, uiAtom, u => ({ ...u, open: toggle(u.open, id) }))
    }
    return
  }
  if (cursor.startsWith('cf:') || cursor.startsWith('hf:')) {
    if (key === 'left' || key === 'h') {
      const parent = cursor.startsWith('cf:') ? 'code' : 'hist'
      await update($, uiAtom, u => ({ ...u, cursor: parent, open: u.open.filter(x => x !== `#${parent}`) }))
      return
    }
    if (key === 'c' || key === 'return' || key === '⏎') {
      const i = Number(cursor.slice(3))
      const f = cursor.startsWith('cf:') ? (await read($, codeAtom)).findings[i] : undefined
      const h = cursor.startsWith('hf:') ? (await read($, gitleaksAtom)).record?.findings[i] : undefined
      const text = f ? `${f.path}:${f.line}` : h ? `${h.file}:${h.line} (${h.commit})` : ''
      if (!text) return
      const r = await $.ui.copy({ text, surface })
      await say($, r.isCopied ? `위치 복사됨: ${text}` : `복사 실패: ${r.reason}`)
    }
    return
  }

  if (key === 'return' || key === '⏎' || key === 'right' || key === 'l' || key === 'left' || key === 'h' || key === ' ') {
    const isOpenKey = key === 'right' || key === 'l'
    const isCloseKey = key === 'left' || key === 'h'
    if (t.kind === 'dir') {
      const open = isDirOpen(scan, ui, t.dir)
      if ((open && isOpenKey) || (!open && isCloseKey)) return
      await update($, uiAtom, u => ({
        ...u,
        dirOpen: open ? u.dirOpen.filter(d => d !== t.dir) : [...u.dirOpen, t.dir],
        dirClosed: open ? [...u.dirClosed, t.dir] : u.dirClosed.filter(d => d !== t.dir),
      }))
    } else if (t.kind === 'file') {
      const open = ui.open.includes(t.file.path)
      if ((open && isOpenKey) || (!open && isCloseKey)) return
      await update($, uiAtom, u => ({ ...u, open: toggle(u.open, t.file.path) }))
    } else if (t.kind === 'key' && isCloseKey) {
      await update($, uiAtom, u => ({ ...u, cursor: `f:${t.file.path}`, open: u.open.filter(x => x !== t.file.path) }))
    } else if (t.kind === 'key') {
      await setMode({ kind: 'edit', file: t.file.path, key: t.key })
    }
    return
  }

  if (t.kind === 'root' || t.kind === 'dir') return
  const file = t.file

  if (key === 'a') return void (await openDialog($, { kind: 'add', file: file.path, key: '', value: '', error: '' }))
  if (key === 'd') return void (await setMode({ kind: 'dup', file: file.path }))
  if (key === 'i' && !file.isTemplate && file.isIgnored === false) {
    const note = await ensureIgnored($, root, file.path)
    await rescan($)
    await say($, `${file.path}: ${note}`)
    return
  }
  if (key === 'u' && file.isTracked) {
    const answer = await $.ui.ask(`${file.path}를 git 인덱스에서 제거할까요? (파일은 유지, 이전 커밋 기록엔 남음)`, ['제거', '취소'])
    if (answer !== '제거') return
    const r = await git($, root, ['rm', '--cached', '-q', '--', file.path])
    const note = r.exitCode === 0 ? await ensureIgnored($, root, file.path) : r.stderr.trim()
    await rescan($)
    await say($, `${file.path}: 추적 해제 · ${note} · 이미 커밋된 키는 교체 필요`)
    return
  }
  if (t.kind !== 'key') return
  if (key === 'c') {
    const value = parseEnv(await readText($, abs(root, file.path))).find(p => p.key === t.key)?.value
    if (value === undefined) return void (await say($, `${t.key} 없음`))
    const r = await $.ui.copy({ text: value, surface })
    await say($, r.isCopied ? `${t.key} 값 복사됨` : `복사 실패: ${r.reason}`)
    return
  }
  if (key === 'e') return void (await setMode({ kind: 'edit', file: file.path, key: t.key }))
  if (key === 'x') {
    const answer = await $.ui.ask(`${file.path}에서 ${t.key}를 삭제할까요? 되돌릴 수 없습니다.`, ['삭제', '취소'])
    if (answer !== '삭제') return
    const path = abs(root, file.path)
    await $.fs.write(path, removeKey(await readText($, path), t.key))
    await rescan($)
    await say($, `${t.key} 삭제`)
  }
}

const newTarget = (d: Extract<EnvDialog, { kind: 'new' }>) => {
  const name = d.name.trim().replace(/^\.\//, '') || '.env'
  return d.atRoot || d.dir === '' || name.includes('/') ? name.replace(/^\//, '') : `${d.dir}/${name}`
}

async function openDialog($: $, d: EnvDialog): Promise<void> {
  await update($, dialogAtom, () => d)
  await update($, uiAtom, u => ({ ...u, mode: null, message: '' }))
  await $.ui.focus({ requestId: PANE, key: d.kind === 'new' ? 'dlg-name' : 'dlg-key' }).catch(() => undefined)
}

async function closeDialog($: $, message: string): Promise<void> {
  await update($, dialogAtom, () => null)
  await closeMode($, message)
}

/** Splits `KEY=value` typed into the key field; a value field typed apart wins. */
function keyValue(d: { key: string; value: string }): { key: string; value: string } {
  const at = d.key.indexOf('=')
  if (at < 0) return { key: d.key.trim(), value: d.value }
  return { key: d.key.slice(0, at).trim(), value: d.value !== '' ? d.value : d.key.slice(at + 1).trim() }
}

async function submitDialog($: $, scan: EnvScan): Promise<void> {
  const d = await read($, dialogAtom)
  if (!d) return
  const { root } = scan
  const fail = (error: string) => update($, dialogAtom, x => (x ? { ...x, error } : x))
  const kv = keyValue(d)
  if (kv.key !== '' && !isValidKey(kv.key)) return void (await fail(`잘못된 키 이름: ${kv.key}`))

  if (d.kind === 'add') {
    if (kv.key === '') return void (await fail('KEY 입력 필요'))
    await setValue($, root, d.file, kv.key, kv.value)
    await rescan($)
    await update($, uiAtom, u => ({ ...u, open: u.open.includes(d.file) ? u.open : [...u.open, d.file], cursor: `k:${d.file}\u0000${kv.key}` }))
    return closeDialog($, `${d.file}: ${kv.key} 저장`)
  }

  const rel = newTarget(d)
  if (await $.fs.exists(abs(root, rel))) return void (await fail(`${rel} 이미 존재`))
  await $.fs.write(abs(root, rel), kv.key === '' ? '' : setKey('', kv.key, kv.value))
  const note = isTemplateName(baseOf(rel)) ? '템플릿 파일' : await ensureIgnored($, root, rel)
  const unmatched = matchesAny(baseOf(rel), cfg.patterns) ? '' : ' · 패턴 미일치로 트리에 안 보임'
  await rescan($)
  const dir = dirOf(rel)
  await update($, uiAtom, u => ({
    ...u, open: [...u.open, rel], cursor: `f:${rel}`,
    dirOpen: dir === '' || u.dirOpen.includes(dir) ? u.dirOpen : [...u.dirOpen, dir],
  }))
  return closeDialog($, `${rel} 생성 · ${note}${unmatched}${kv.key ? ` · ${kv.key} 저장` : ''}`)
}

async function submitMode($: $, scan: EnvScan, mode: EnvMode | null, raw: string): Promise<void> {
  if (!mode) return
  const { root } = scan
  const value = raw.trim()

  if (mode.kind === 'setting') {
    const note = await setOption($, mode.field, value)
    return closeMode($, note)
  }

  if (mode.kind === 'edit') {
    await setValue($, root, mode.file, mode.key, raw)
    await rescan($)
    return closeMode($, `${mode.key} 수정됨`)
  }

  const rel = value.replace(/^\.\//, '')
  if (!rel) return
  const target = rel.includes('/') ? rel : dirOf(mode.file) === '' ? rel : `${dirOf(mode.file)}/${rel}`
  if (await $.fs.exists(abs(root, target))) return void (await hint($, `${target} 이미 존재`))
  const source = await readText($, abs(root, mode.file))
  const isTemplate = isTemplateName(baseOf(target))
  const text = isTemplate
    ? source.split(/\r?\n/).map(l => l.replace(/^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=).*$/, '$1')).join('\n')
    : source
  await $.fs.write(abs(root, target), text)
  const note = isTemplate ? '템플릿: 값 비움' : await ensureIgnored($, root, target)
  await rescan($)
  await update($, uiAtom, u => ({ ...u, cursor: `f:${target}` }))
  return closeMode($, `${mode.file} → ${target} · ${note}`)
}

// ── storing secrets ────────────────────────────────────────────────

/** Puts each secret into `file` (reusing a key that holds the same value) and gitignores it. */
async function storeSecrets($: $, root: string, file: string, secrets: Found[]) {
  const path = abs(root, file)
  let text = await readText($, path)
  const known = parseEnv(text)
  const keys = new Set(known.map(p => p.key))
  const stored = new Map<string, { key: string; detected: string; isNew: boolean }>()
  for (const s of secrets) {
    if (stored.has(s.value)) continue
    const same = known.find(p => p.value === s.value)
    if (same) {
      stored.set(s.value, { key: same.key, detected: s.key, isNew: false })
      continue
    }
    const key = uniqueKey(keys, s.key)
    keys.add(key)
    text = setKey(text, key, s.value)
    stored.set(s.value, { key, detected: s.key, isNew: true })
  }
  await $.fs.write(path, text)
  const ignoreNote = isTemplateName(baseOf(file)) ? 'template file' : await ensureIgnored($, root, file)
  return { path, keys, stored, ignoreNote }
}

// ── keys written into source files ─────────────────────────────────

const MAX_CODE_FILES = 4000
const MAX_CODE_BYTES = 512_000
const MAX_FINDINGS = 200
let codeScanning: Promise<CodeScan> | null = null

async function listCodeFiles($: $, scan: EnvScan): Promise<string[]> {
  if (scan.gitRoot) {
    const r = await git($, scan.root, ['-c', 'core.quotePath=false', 'ls-files', '-co', '--exclude-standard', '-z'])
    if (r.exitCode === 0) return [...lines(r.stdout)]
  }
  const out: string[] = []
  const visit = async (rel: string, depth: number) => {
    const entries = await $.fs.list(rel === '' ? scan.root : `${scan.root}/${rel}`).catch(() => [])
    for (const entry of entries) {
      if (out.length >= MAX_CODE_FILES) return
      const path = rel === '' ? entry.name : `${rel}/${entry.name}`
      if (entry.kind === 'dir' && depth < cfg.maxDepth && !SKIP_DIRS.has(entry.name)) await visit(path, depth + 1)
      else if (entry.kind === 'file' && entry.size <= MAX_CODE_BYTES) out.push(path)
    }
  }
  await visit('', 0)
  return out
}

async function findingsIn($: $, root: string, path: string): Promise<CodeFinding[]> {
  if (matchesAny(baseOf(path), cfg.patterns) || !isScannableCode(path)) return []
  const text = await $.fs.read(`${root}/${path}`).catch(() => '')
  if (text === '' || text.length > MAX_CODE_BYTES || text.includes('\0')) return []
  // `env-manager:ignore-file` near the top skips the file; `gitleaks:allow` or
  // `env-manager:allow` on a line skips that line, as gitleaks does
  if (/env-manager:ignore-file/.test(text.slice(0, 2000))) return []
  const lineText = (at: number) => text.slice(text.lastIndexOf('\n', at - 1) + 1, (text.indexOf('\n', at) + 1 || text.length + 1) - 1)
  return findSecretsInCode(text)
    .filter(f => !/gitleaks:allow|env-manager:allow/.test(lineText(f.start)))
    .map(f => ({ path, line: lineOf(text, f.start), rule: f.key, masked: mask(f.value) }))
}

async function doScanCode($: $, scan: EnvScan): Promise<CodeScan> {
  await update($, codeAtom, (c): CodeScan => ({ ...c, status: 'running' }))
  const files = (await listCodeFiles($, scan)).filter(p => !matchesAny(baseOf(p), cfg.patterns) && isScannableCode(p)).slice(0, MAX_CODE_FILES)
  const findings: CodeFinding[] = []
  for (const path of files) {
    if (findings.length >= MAX_FINDINGS) break
    findings.push(...(await findingsIn($, scan.root, path)))
  }
  const result: CodeScan = { status: 'done', files: files.length, findings: findings.slice(0, MAX_FINDINGS), at: await $.clock.now() }
  await update($, codeAtom, () => result)
  return result
}

function scanCode($: $, scan: EnvScan): Promise<CodeScan> {
  if (!codeScanning) codeScanning = doScanCode($, scan).finally(() => { codeScanning = null })
  return codeScanning
}

/** After a write: refresh the findings of that one file. */
async function rescanCodeFile($: $, filePath: string): Promise<void> {
  const scan = await read($, scanAtom)
  if (!scan) return
  const rel = filePath.startsWith(`${scan.root}/`) ? filePath.slice(scan.root.length + 1) : filePath.replace(/^\.\//, '')
  if (rel.startsWith('/')) return
  const fresh = await findingsIn($, scan.root, rel)
  await update($, codeAtom, c => ({ ...c, findings: [...c.findings.filter(f => f.path !== rel), ...fresh].slice(0, MAX_FINDINGS) }))
}

// ── gitleaks over the commit history ───────────────────────────────

const storeKey = (top: string) => `gitleaks:${top}`

/** Checks for the binary, loads the last run of this repo, and runs again in auto mode when HEAD moved. */
async function prepareGitleaks($: $, scan: EnvScan): Promise<void> {
  const v = await $.process.run(['gitleaks', 'version'], { cwd: scan.root, timeoutMs: 10_000 }).catch(() => null)
  const version = v && v.exitCode === 0 ? v.stdout.trim() : ''
  const saved = scan.gitRoot ? ((await $.store.get(storeKey(scan.gitRoot))) as GitleaksRecord | undefined) : undefined
  await update($, gitleaksAtom, g => ({ ...g, version, record: saved ?? null }))
  if (cfg.gitleaks !== 'auto' || !version || !scan.gitRoot) return
  const head = (await git($, scan.root, ['rev-parse', 'HEAD'])).stdout.trim()
  if (head && head !== saved?.head) void runGitleaks($, scan).catch(() => undefined)
}

type GitleaksJson = { RuleID?: string; File?: string; StartLine?: number; Commit?: string; Date?: string }

export function parseGitleaksReport(stdout: string): HistoryFinding[] {
  const start = stdout.indexOf('[')
  if (start < 0) return []
  const data = JSON.parse(stdout.slice(start)) as GitleaksJson[]
  return data.map(f => ({ rule: f.RuleID ?? '', file: f.File ?? '', line: f.StartLine ?? 0, commit: f.Commit ?? '', date: f.Date ?? '' }))
}

async function runGitleaks($: $, scan: EnvScan): Promise<GitleaksRecord | null> {
  const top = scan.gitRoot
  const state = await read($, gitleaksAtom)
  if (!top || !state.version || state.running) return null
  await update($, gitleaksAtom, g => ({ ...g, running: true }))
  const head = (await git($, top, ['rev-parse', 'HEAD'])).stdout.trim()
  let record: GitleaksRecord
  try {
    const r = await $.process.run(
      ['gitleaks', 'git', '--no-banner', '--redact', '--report-format', 'json', '--report-path', '-', '--exit-code', '0', '--log-level', 'error', top],
      { cwd: top, timeoutMs: 600_000 },
    )
    const findings = parseGitleaksReport(r.stdout)
    record = { ranAt: await $.clock.now(), head, version: state.version, count: findings.length, findings: findings.slice(0, MAX_FINDINGS), error: r.exitCode === 0 ? '' : r.stderr.trim().slice(0, 300) }
  } catch (err) {
    record = { ranAt: await $.clock.now(), head, version: state.version, count: 0, findings: [], error: String(err).slice(0, 300) }
  }
  await $.store.set(storeKey(top), record)
  await update($, gitleaksAtom, g => ({ ...g, running: false, record }))
  $.ui.toast(record.error ? `gitleaks 실패: ${record.error}` : `gitleaks: 커밋 기록 속 키 ${record.count}건`, { timeoutMs: 8000 })
  return record
}

// ── settings page ──────────────────────────────────────────────────

type Setting = { field: string; label: string; fallback: string; options?: string[]; hint: string }

const SETTINGS: Setting[] = [
  { field: 'intercept', label: '프롬프트 비밀값 가로채기', fallback: 'on', options: ['on', 'off'], hint: '프롬프트에 붙여넣은 키를 env 파일로 옮김' },
  { field: 'guardWrites', label: 'Claude 코드 쓰기 검사', fallback: 'on', options: ['on', 'off'], hint: 'Claude가 코드에 키를 쓰면 막고 env 파일로 옮김' },
  { field: 'scanFiles', label: '하드코드 시크릿 검사', fallback: 'on', options: ['on', 'off'], hint: '프로젝트 파일에 적힌 키를 찾음' },
  { field: 'gitleaks', label: 'gitleaks 커밋 기록 검사', fallback: 'manual', options: ['off', 'manual', 'auto'], hint: 'manual: 직접 실행 · auto: HEAD가 바뀌면 세션 시작 때 실행' },
  { field: 'patterns', label: '추적 패턴', fallback: '.env .env.*', hint: '파일 이름 glob, 공백으로 구분' },
  { field: 'defaultFile', label: '기본 env 파일', fallback: '.env', hint: '가로챈 키를 저장할 파일' },
  { field: 'maxDepth', label: '검사 깊이', fallback: '5', hint: '작업 폴더 아래 몇 단계까지' },
  { field: 'checkMinutes', label: '재검사 간격(분)', fallback: '10', hint: 'Claude 응답이 끝날 때 마지막 검사 후 이 시간이 지났으면 백그라운드 재검사' },
  { field: 'renamePrompt', label: '키 이름 지시문', fallback: DEFAULT_RENAME_PROMPT, hint: 'Claude에게 주는 지시. {file} {path} {stored} {keys} {tool}' },
]

function buildSettingsRows(gl: GitleaksState): EnvRow[] {
  const rows: EnvRow[] = []
  for (const f of SETTINGS) {
    const value = cfg.raw[f.field] ?? f.fallback
    const shown = f.field === 'renamePrompt' ? (value === DEFAULT_RENAME_PROMPT ? '기본값' : '사용자 지정') : value
    const color = value === 'on' || value === 'auto' ? 'success' : value === 'off' ? '' : 'suggestion'
    rows.push({
      id: `set:${f.field}`,
      left: [{ t: f.options ? '◆ ' : '✎ ', dim: true }, { t: f.label }],
      right: [{ t: shown.length > 28 ? `${shown.slice(0, 27)}…` : shown, c: color, dim: color === '', b: color !== '' }],
    })
    if (f.field !== 'gitleaks') continue
    const installed = gl.version === null ? '확인 중…' : gl.version ? `설치됨 ${gl.version}` : '설치 안 됨 (brew install gitleaks)'
    rows.push({ id: 'set:gl-info', left: [{ t: '    ' }, { t: installed, dim: true }], right: [] })
    const rec = gl.record
    const last = gl.running ? '실행 중…'
      : rec ? `마지막 실행 ${new Date(rec.ranAt).toISOString().slice(0, 16).replace('T', ' ')} · HEAD ${rec.head.slice(0, 7)} · ${rec.error ? '실패' : `${rec.count}건`}`
        : '실행 기록 없음'
    rows.push({ id: 'set:gl-last', left: [{ t: '    ' }, { t: last, dim: !rec?.count, c: rec?.count ? 'error' : '' }], right: [] })
    if (gl.version) rows.push({ id: 'set:gl-run', left: [{ t: '    ' }, { t: '▶ 지금 실행', c: 'suggestion' }], right: [] })
  }
  return rows
}

function settingsHints(cursor: string): Hint[] {
  const field = SETTINGS.find(f => `set:${f.field}` === cursor)
  const nav: Hint[] = [{ key: '↑↓', label: '이동' }]
  const back: Hint = { key: 's', label: '트리로' }
  if (cursor === 'set:gl-run') return [...nav, { key: '⏎', label: '실행' }, back]
  if (!field) return [...nav, back]
  return [...nav, { key: '⏎', label: field.options ? '바꾸기' : '수정' }, back]
}

/** Writes one of this mod's userConfig fields as the /config menu would (the module reloads with it). */
async function setOption($: $, field: string, value: string): Promise<string> {
  const rows = await $.config.list()
  const row = rows.find(r => r.key === `${PLUGIN}.${field}`) ?? rows.find(r => r.provider.plugin === PLUGIN && r.key.endsWith(`.${field}`))
  if (!row) return `설정 항목 없음: ${field} (/config 사용)`
  const r = await $.config.set({ key: row.key, value })
  if (r.deny !== undefined) return `변경 거부: ${r.deny}`
  cfg.raw = { ...cfg.raw, [field]: value }
  return `${SETTINGS.find(f => f.field === field)?.label ?? field} → ${value || '기본값'}`
}

async function actSetting($: $, scan: EnvScan, cursor: string, key: string): Promise<void> {
  const isPress = key === 'return' || key === '⏎' || key === ' ' || key === 'right' || key === 'l'
  if (cursor === 'set:gl-run') {
    if (!isPress) return
    if (!scan.gitRoot) return void (await say($, 'git 저장소가 아님'))
    await say($, 'gitleaks 실행 중…')
    const rec = await runGitleaks($, scan)
    await say($, rec ? (rec.error ? `gitleaks 실패: ${rec.error}` : `gitleaks 완료: ${rec.count}건`) : 'gitleaks를 실행할 수 없음')
    return
  }
  const field = SETTINGS.find(f => `set:${f.field}` === cursor)
  if (!field) return
  if (field.options) {
    if (!isPress && key !== 'left' && key !== 'h') return
    const now = cfg.raw[field.field] ?? field.fallback
    const at = field.options.indexOf(now)
    const step = key === 'left' || key === 'h' ? -1 : 1
    const nextValue = field.options[(at + step + field.options.length) % field.options.length] ?? field.fallback
    await say($, await setOption($, field.field, nextValue))
    return
  }
  if (isPress || key === 'e') await update($, uiAtom, (u): EnvUi => ({ ...u, mode: { kind: 'setting', field: field.field }, message: field.hint }))
}
