import { expect, test } from 'claude-code/testing'

const GH = 'ghp' + '_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fake(on: any, files: Record<string, string>, extra: { lsFiles?: string[]; gitleaks?: string } = {}) {
  on('session.cwd', () => ({ value: '/proj' }))
  on('fs.read', (_: unknown, e: { path: string }) => {
    const text = files[e.path]
    if (text === undefined) throw new Error('ENOENT')
    return { value: text }
  })
  on('fs.write', (_: unknown, e: { path: string; text: string }) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('fs.exists', (_: unknown, e: { path: string }) => ({ value: e.path in files }))
  on('fs.list', () => ({ value: [] }))
  on('process.run', (_: unknown, e: { argv: string[] }) => {
    const a = e.argv.join(' ')
    if (a.startsWith('gitleaks version')) return { value: extra.gitleaks === undefined ? { exitCode: 127, stdout: '', stderr: '' } : { exitCode: 0, stdout: '8.28.0\n', stderr: '' } }
    if (a.startsWith('gitleaks git')) return { value: { exitCode: 0, stdout: extra.gitleaks ?? '[]', stderr: '' } }
    if (!extra.lsFiles) return { value: { exitCode: 128, stdout: '', stderr: '' } }
    if (a.includes('--show-toplevel')) return { value: { exitCode: 0, stdout: '/proj\n', stderr: '' } }
    if (a.includes('rev-parse HEAD')) return { value: { exitCode: 0, stdout: 'abcdef1234567\n', stderr: '' } }
    if (a.includes('ls-files -co')) return { value: { exitCode: 0, stdout: extra.lsFiles.join('\0'), stderr: '' } }
    if (a.includes('check-ignore -q')) return { value: { exitCode: 1, stdout: '', stderr: '' } }
    return { value: { exitCode: 0, stdout: '', stderr: '' } }
  })
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('command.register', () => ({ value: { command: 'env' } }))
  on('tool.register', () => ({ value: { tool: 'mcp__env-manager__rename_key' } }))
  on('ui.toast', () => ({ value: undefined }))
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
  on('tool.call', () => ({ result: 'written' }))
}

test('a Write that hardcodes a key is refused and the key moves to .env', async ($, on) => {
  const files: Record<string, string> = {}
  fake(on, files)
  const r = await $.tool.call({ tool: 'Write', file_path: '/proj/src/github.ts', content: `const token = "${GH}"\n` })
  expect(String(r.isError ? r.text : r.deny ?? '').includes('process.env.KEY')).toBe(true)
  expect(files['/proj/.env']).toBe(`GITHUB_PAT=${GH}\n`)
  expect(files['/proj/src/github.ts']).toBeUndefined()
})

test('writing a key into an env file is allowed', async ($, on) => {
  const files: Record<string, string> = {}
  fake(on, files)
  const r = await $.tool.call({ tool: 'Write', file_path: '/proj/.env.local', content: `GITHUB_PAT=${GH}\n` })
  expect(r.isError).toBeUndefined()
  expect(r.deny).toBeUndefined()
})

test('guardWrites off lets the write through', { options: { guardWrites: 'off' } }, async ($, on) => {
  const files: Record<string, string> = {}
  fake(on, files)
  const r = await $.tool.call({ tool: 'Edit', file_path: '/proj/src/a.ts', old_string: 'x', new_string: GH })
  expect(r.deny).toBeUndefined()
  expect(r.isError).toBeUndefined()
})

test('/env scan lists keys hardcoded in source files, skipping env files and lockfiles', async ($, on) => {
  const files: Record<string, string> = {
    '/proj/src/a.ts': `// x\nconst k = "${GH}"\n`,
    '/proj/src/b.ts': 'export const ok = 1\n',
    '/proj/package-lock.json': `"${GH}"`,
    '/proj/.env': `GITHUB_PAT=${GH}\n`,
  }
  fake(on, files, { lsFiles: ['src/a.ts', 'src/b.ts', 'package-lock.json', '.env'] })
  await $.session.start({ cwd: '/proj', surface: 'terminal', isInteractive: true })
  const r = await $.command.run({ command: 'env', args: 'scan' })
  expect(r.text?.includes('하드코드 시크릿 1건 (파일 2개 검사)')).toBe(true)
  expect(r.text?.includes('src/a.ts:2  GITHUB_PAT  ghp_a')).toBe(true)
  expect(r.text?.includes(GH)).toBe(false)
})

test('gitleaks:allow on a line and env-manager:ignore-file at the top skip findings', async ($, on) => {
  const files: Record<string, string> = {
    '/proj/src/a.ts': `const k = "${GH}" // gitleaks:allow\n`,
    '/proj/src/b.ts': `// env-manager:ignore-file\nconst k = "${GH}"\n`,
    '/proj/src/c.ts': `const k = "${GH}"\n`,
  }
  fake(on, files, { lsFiles: ['src/a.ts', 'src/b.ts', 'src/c.ts'] })
  await $.session.start({ cwd: '/proj', surface: 'terminal', isInteractive: true })
  const r = await $.command.run({ command: 'env', args: 'scan' })
  expect(r.text?.includes('하드코드 시크릿 1건')).toBe(true)
  expect(r.text?.includes('src/c.ts:1')).toBe(true)
})

const PANE = {
  plugin: 'env-manager', component: 'Pane', requestId: 'env-manager',
  props: { title: 'env-manager', isFocused: true, bodyColumns: 80, placement: 'dock', scroll: { offset: 0, bodyRows: 30 }, view: {} },
} as const

test('the settings page flips an option through /config and runs gitleaks, keeping the result', async ($, on) => {
  const files: Record<string, string> = {}
  const report = JSON.stringify([{ RuleID: 'aws-access-token', File: 'old/config.js', StartLine: 3, Commit: 'deadbeefcafe', Date: '2024-01-01' }])
  fake(on, files, { lsFiles: [], gitleaks: report })
  const store: Record<string, unknown> = {}
  on('store.get', (_: unknown, e: { key: string }) => ({ value: store[e.key] }))
  on('store.set', (_: unknown, e: { key: string; value: unknown }) => {
    store[e.key] = e.value
    return { value: undefined }
  })
  const sets: unknown[] = []
  on('config.list', () => ({ value: [{ key: 'env-manager.intercept', label: 'x', kind: 'choice', value: 'on', options: ['on', 'off'], provider: { plugin: 'env-manager', tier: 'user' }, isLocked: false }] }))
  on('config.set', (_: unknown, e: { key: string; value: unknown }) => {
    sets.push([e.key, e.value])
    return { value: e.value }
  })
  await $.session.start({ cwd: '/proj', surface: 'terminal', isInteractive: true })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.key({ key: 's', in: 'rows' })
  const drawn = JSON.stringify(await ui.drawn({ in: 'rows' }))
  expect(drawn.includes('프롬프트 비밀값 가로채기')).toBe(true)
  expect(drawn.includes('설치됨 8.28.0')).toBe(true)

  await ui.key({ key: 'return', in: 'rows' }) // first row: intercept on → off
  expect(sets).toEqual([['env-manager.intercept', 'off']])

  for (let i = 0; i < 6; i++) await ui.key({ key: 'down', in: 'rows' }) // … gitleaks, gl-info, gl-last, gl-run
  await ui.key({ key: 'return', in: 'rows' })
  expect(JSON.stringify(store['gitleaks:/proj']).includes('"count":1')).toBe(true)
  expect(JSON.stringify(await ui.drawn({ in: 'rows' })).includes('1건')).toBe(true)
  await ui.unmount()
})
