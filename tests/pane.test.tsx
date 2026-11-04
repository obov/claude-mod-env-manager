import { expect, test } from 'claude-code/testing'

const PANE = {
  plugin: 'env-manager',
  component: 'Pane',
  requestId: 'env-manager',
  props: { title: 'env-manager', isFocused: true, bodyColumns: 80, placement: 'dock', scroll: { offset: 0, bodyRows: 30 }, view: {} },
} as const

type Entry = { name: string; kind: 'file' | 'dir' }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type On = any

function fakeProject(on: On, files: Record<string, string>, tree: Record<string, Entry[]>, git: { ignored?: string; tracked?: string } | null) {
  on('session.cwd', () => ({ value: '/proj' }))
  on('fs.list', (_: unknown, e: { path?: string }) => {
    const extra = Object.keys(files)
      .filter(f => f.slice(0, f.lastIndexOf('/')) === e.path && !(tree[e.path ?? ''] ?? []).some(x => `${e.path}/${x.name}` === f))
      .map(f => ({ name: f.slice(f.lastIndexOf('/') + 1), kind: 'file' as const }))
    return { value: [...(tree[e.path ?? ''] ?? []), ...extra].map(x => ({ ...x, size: 1, mtimeMs: 0, isLink: false })) }
  })
  on('fs.read', (_: unknown, e: { path: string }) => ({ value: files[e.path] ?? '' }))
  on('fs.exists', (_: unknown, e: { path: string }) => ({ value: e.path in files }))
  on('fs.write', (_: unknown, e: { path: string; text: string }) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('process.run', (_: unknown, e: { argv: string[] }) => {
    if (!git) return { value: { exitCode: 128, stdout: '', stderr: '' } }
    const a = e.argv.join(' ')
    if (a.includes('--show-toplevel')) return { value: { exitCode: 0, stdout: '/proj\n', stderr: '' } }
    if (a.includes('check-ignore')) return { value: { exitCode: 0, stdout: (git.ignored ?? '').replace(/\n/g, '\0'), stderr: '' } }
    if (a.includes('ls-files')) return { value: { exitCode: 0, stdout: (git.tracked ?? '').replace(/\n/g, '\0'), stderr: '' } }
    return { value: { exitCode: 0, stdout: '\n', stderr: '' } }
  })
  on('clock.now', () => ({ value: 1 }))
  on('command.register', () => ({ value: { command: 'env' } }))
  on('tool.register', () => ({ value: { tool: 'mcp__env-manager__rename_key' } }))
  on('ui.toast', () => ({ value: undefined }))
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
}

test('the tree shows folders and env files one per row, values masked when opened', async ($, on) => {
  const files = {
    '/proj/.env': 'OPENAI_API_KEY=sk-' + 'abcdefghijklmnop\nSHORT=abc\n',
    '/proj/apps/web/.env.local': 'TOKEN=1234567890\n',
    '/proj/.env.example': 'OPENAI_API_KEY=\n',
  }
  const tree: Record<string, Entry[]> = {
    '/proj': [{ name: '.env', kind: 'file' }, { name: '.env.example', kind: 'file' }, { name: 'apps', kind: 'dir' }, { name: 'node_modules', kind: 'dir' }],
    '/proj/apps': [{ name: 'web', kind: 'dir' }],
    '/proj/apps/web': [{ name: '.env.local', kind: 'file' }],
  }
  fakeProject(on, files, tree, { ignored: 'apps/web/.env.local\n', tracked: '.env.example\n' })
  await $.session.start({ cwd: '/proj', surface: 'terminal', isInteractive: true })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  const text = async () => JSON.stringify(await ui.drawn({ in: 'rows' }))
  let drawn = await text()
  expect(drawn.includes('apps/')).toBe(true)
  expect(drawn.includes('node_modules')).toBe(false)
  expect(drawn.includes('✗ 미등록')).toBe(true)
  expect(drawn.includes('✓ ignored')).toBe(true)
  expect(drawn.includes('템플릿')).toBe(true)

  // root, apps/, web/, .env.local, .env, .env.example: move to .env and open it
  for (let i = 0; i < 4; i++) await ui.key({ key: 'down', in: 'rows' })
  await ui.key({ key: 'return', in: 'rows' })
  drawn = await text()
  expect(drawn.includes('sk-ab**************')).toBe(true)
  expect(drawn.includes('"***"')).toBe(true)
  expect(drawn.includes('abcdefghijklmnop')).toBe(false)
  await ui.unmount()
})

test('n opens the new-file input in the selected folder; ✖ closes it', async ($, on) => {
  const files: Record<string, string> = {}
  const tree: Record<string, Entry[]> = { '/proj': [{ name: 'api', kind: 'dir' }], '/proj/api': [] }
  fakeProject(on, files, tree, null)
  await $.session.start({ cwd: '/proj', surface: 'terminal', isInteractive: true })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.key({ key: 'down', in: 'rows' })
  await ui.key({ key: 'n', in: 'rows' })
  expect(await ui.find({ key: 'mode-input:new:api' })).toBeDefined()
  await ui.press({ key: 'cancel-input' })
  expect(await ui.find({ key: 'mode-input:new:api' })).toBeUndefined()

  await ui.key({ key: 'n', in: 'rows' })
  await ui.input({ key: 'mode-input:new:api', text: '' })
  expect(files['/proj/api/.env']).toBe('')
  expect(JSON.stringify(await ui.drawn({ in: 'rows' })).includes('(비어 있음')).toBe(true)
  await ui.unmount()
})

test('a, c and e act on the selected key', async ($, on) => {
  const files: Record<string, string> = { '/proj/.env': 'A=hello12345\n' }
  fakeProject(on, files, { '/proj': [{ name: '.env', kind: 'file' }] }, null)
  let copied = ''
  on('ui.copy', (_: unknown, e: { text: string }) => {
    copied = e.text
    return { value: { isCopied: true } }
  })
  await $.session.start({ cwd: '/proj', surface: 'terminal', isInteractive: true })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.key({ key: 'down', in: 'rows' }) // .env
  await ui.key({ key: 'a', in: 'rows' })
  await ui.input({ key: 'mode-input:add:.env', text: 'B=world67890' })
  expect(files['/proj/.env']).toBe('A=hello12345\nB=world67890\n')

  await ui.key({ key: 'c', in: 'rows' }) // cursor moved to the new key B
  expect(copied).toBe('world67890')
  await ui.key({ key: 'e', in: 'rows' })
  await ui.input({ key: 'mode-input:edit:.env:B', text: 'changed' })
  expect(files['/proj/.env']).toBe('A=hello12345\nB=changed\n')
  await ui.unmount()
})

test('keys typed in Korean IME mode act like their Latin keys', async ($, on) => {
  const files: Record<string, string> = { '/proj/.env': 'A=hello12345\n' }
  fakeProject(on, files, { '/proj': [{ name: '.env', kind: 'file' }] }, null)
  await $.session.start({ cwd: '/proj', surface: 'terminal', isInteractive: true })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.key({ key: 'ㅓ', in: 'rows' }) // j: down to .env
  await ui.key({ key: 'ㅁ', in: 'rows' }) // a: add key
  expect(await ui.find({ key: 'mode-input:add:.env' })).toBeDefined()
  await ui.press({ key: 'cancel-input' })
  await ui.key({ key: 'ㄴ', in: 'rows' }) // s: settings
  expect(JSON.stringify(await ui.drawn({ in: 'rows' })).includes('프롬프트 비밀값 가로채기')).toBe(true)
  await ui.unmount()
})
