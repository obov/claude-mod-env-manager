import { expect, test } from 'claude-code/testing'

const SECRET = 'sk-' + 'ant-api03-abcdefghijklmnopqrstuvwxyz0123456789'

test('a secret typed into a prompt moves into .env and the model gets a placeholder', async ($, on) => {
  const files: Record<string, string> = { '/proj/.env': 'EXISTING=1\n' }
  const runs: string[][] = []

  on('session.cwd', () => ({ value: '/proj' }))
  on('fs.read', (_, e) => {
    const text = files[e.path]
    if (text === undefined) throw new Error('ENOENT')
    return { value: text }
  })
  on('fs.write', (_, e) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('fs.list', () => ({ value: [] }))
  on('process.run', (_, e) => {
    runs.push([...e.argv])
    const args = e.argv.join(' ')
    if (args.includes('--show-toplevel')) return { value: { exitCode: 0, stdout: '/proj\n', stderr: '' } }
    if (args.includes('--show-prefix')) return { value: { exitCode: 0, stdout: '\n', stderr: '' } }
    if (args.includes('check-ignore')) return { value: { exitCode: 1, stdout: '', stderr: '' } }
    return { value: { exitCode: 0, stdout: '', stderr: '' } }
  })
  on('ui.toast', () => ({ value: undefined }))

  let seen: { text: string; context?: readonly string[] } | undefined
  on('prompt.submit', (_, e) => {
    seen = { text: e.text, context: e.context }
    return { text: e.text, context: e.context }
  })

  await $.prompt.submit({ text: `이 키로 연결해줘 ${SECRET} 부탁` })

  expect(seen?.text).toBe('이 키로 연결해줘 [env:.env#ANTHROPIC_API_KEY] 부탁')
  expect(seen?.text.includes(SECRET)).toBe(false)
  expect(files['/proj/.env']).toBe(`EXISTING=1\nANTHROPIC_API_KEY=${SECRET}\n`)
  expect(files['/proj/.gitignore']).toBe('/.env\n')
  const context = seen?.context?.join('\n') ?? ''
  expect(context.includes('/proj/.env')).toBe(true)
  expect(context.includes('mcp__env-manager__rename_key')).toBe(true)
  expect(context.includes(SECRET)).toBe(false)
  expect(context.includes('sk-an****')).toBe(true)
})

test('NAME=value in a prompt keeps the name the user gave', async ($, on) => {
  const files: Record<string, string> = {}
  on('session.cwd', () => ({ value: '/proj' }))
  on('fs.read', (_, e) => {
    const text = files[e.path]
    if (text === undefined) throw new Error('ENOENT')
    return { value: text }
  })
  on('fs.write', (_, e) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('fs.list', () => ({ value: [] }))
  on('process.run', () => ({ value: { exitCode: 128, stdout: '', stderr: 'not a git repo' } }))
  on('ui.toast', () => ({ value: undefined }))
  let text = ''
  on('prompt.submit', (_, e) => {
    text = e.text
    return { text: e.text }
  })

  await $.prompt.submit({ text: 'DB_PASSWORD=hunter2hunter2 로 설정' })

  expect(text).toBe('DB_PASSWORD=[env:.env#DB_PASSWORD] 로 설정')
  expect(files['/proj/.env']).toBe('DB_PASSWORD=hunter2hunter2\n')
})

test('a bare random token with no known prefix is caught; hashes and words are not', async ($, on) => {
  const files: Record<string, string> = {}
  on('session.cwd', () => ({ value: '/proj' }))
  on('fs.read', (_, e) => {
    const text = files[e.path]
    if (text === undefined) throw new Error('ENOENT')
    return { value: text }
  })
  on('fs.write', (_, e) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('fs.list', () => ({ value: [] }))
  on('process.run', () => ({ value: { exitCode: 128, stdout: '', stderr: '' } }))
  on('ui.toast', () => ({ value: undefined }))
  let text = ''
  on('prompt.submit', (_, e) => {
    text = e.text
    return { text: e.text }
  })

  const fake = 'Zq7LmP2xR9tB4vK8nW3yH6jD5sF1gA0c'
  const sha = 'e83c5163316f89bfbde7d9ab23ca2e25604af290'
  await $.prompt.submit({ text: `키 ${fake} 커밋 ${sha} 함수 handlePromptSubmitForUser 경로 src/components/ApiKeyManagerPanel2024.tsx` })

  expect(text).toBe(`키 [env:.env#API_KEY] 커밋 ${sha} 함수 handlePromptSubmitForUser 경로 src/components/ApiKeyManagerPanel2024.tsx`)
  expect(files['/proj/.env']).toBe(`API_KEY=${fake}\n`)
})

const setup = (on: Parameters<Parameters<typeof test>[1]>[1], files: Record<string, string>, seen: { context: string }) => {
  on('session.cwd', () => ({ value: '/proj' }))
  on('fs.read', (_, e) => {
    const text = files[e.path]
    if (text === undefined) throw new Error('ENOENT')
    return { value: text }
  })
  on('fs.write', (_, e) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('fs.list', () => ({ value: [] }))
  on('process.run', () => ({ value: { exitCode: 128, stdout: '', stderr: '' } }))
  on('ui.toast', () => ({ value: undefined }))
  on('prompt.submit', (_, e) => {
    seen.context = (e.context ?? []).join('\n')
    return { text: e.text, context: e.context }
  })
}

test('by default Claude is told to offer a numbered list of key names that fit the context', async ($, on) => {
  const files: Record<string, string> = { '/proj/.env': 'DATABASE_URL=x\n' }
  const seen = { context: '' }
  setup(on, files, seen)
  await $.prompt.submit({ text: 'Zq7LmP2xR9tB4vK8nW3yH6jD5sF1gA0c' })
  expect(seen.context.includes('Suggest 3-5 key names')).toBe(true)
  expect(seen.context.includes('names already in .env (DATABASE_URL)')).toBe(true)
  expect(seen.context.includes('Never ask the user to paste the secret again')).toBe(true)
})

test('the key name prompt comes from settings, the safety rules stay', { options: { renamePrompt: 'CUSTOM: ask about {stored} in {file} via {tool}' } }, async ($, on) => {
  const files: Record<string, string> = {}
  const seen = { context: '' }
  setup(on, files, seen)
  await $.prompt.submit({ text: 'Zq7LmP2xR9tB4vK8nW3yH6jD5sF1gA0c' })
  expect(seen.context.includes('CUSTOM: ask about API_KEY in .env via mcp__env-manager__rename_key')).toBe(true)
  expect(seen.context.includes('Suggest 3-5 key names')).toBe(false)
  expect(seen.context.includes('Never ask the user to paste the secret again')).toBe(true)
})
