import { GITLEAKS_GLOBAL_REGEXES, GITLEAKS_GLOBAL_STOPWORDS, GITLEAKS_RULES } from './rules'

// Pure helpers: parsing, masking, globbing, secret detection. No `$`.

export const SKIP_DIRS = new Set([
  '.git', 'node_modules', '.next', '.nuxt', 'dist', 'build', 'out', 'target',
  'vendor', '.venv', 'venv', '__pycache__', '.cache', '.turbo', 'coverage',
  '.idea', '.vscode', '.terraform', 'Pods', '.gradle',
])

export function globToRegex(glob: string): RegExp {
  const body = glob
    .split('')
    .map(c => (c === '*' ? '[^/]*' : c === '?' ? '[^/]' : c.replace(/[.+^${}()|[\]\\]/g, '\\$&')))
    .join('')
  return new RegExp(`^${body}$`)
}

export function parsePatterns(text: string): RegExp[] {
  return text
    .split(/[\s,]+/)
    .map(s => s.trim())
    .filter(Boolean)
    .map(globToRegex)
}

export function matchesAny(name: string, patterns: RegExp[]): boolean {
  return patterns.some(p => p.test(name))
}

export function isTemplateName(name: string): boolean {
  return /\.(example|sample|template|dist|defaults?)$/i.test(name)
}

export function mask(value: string): string {
  if (value.length === 0) return '(empty)'
  if (value.length <= 5) return '*'.repeat(value.length)
  return value.slice(0, 5) + '*'.repeat(Math.min(value.length - 5, 16))
}

const LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/

export type Parsed = { key: string; value: string; line: number }

function unquote(raw: string): string {
  const text = raw.trim()
  if (text.startsWith('"')) {
    const end = text.lastIndexOf('"')
    const inner = end > 0 ? text.slice(1, end) : text.slice(1)
    return inner.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\')
  }
  if (text.startsWith("'")) {
    const end = text.lastIndexOf("'")
    return end > 0 ? text.slice(1, end) : text.slice(1)
  }
  // strip inline comment: ` #...`
  const hash = text.search(/\s#/)
  return (hash >= 0 ? text.slice(0, hash) : text).trim()
}

export function parseEnv(text: string): Parsed[] {
  const out: Parsed[] = []
  text.split(/\r?\n/).forEach((line, i) => {
    if (/^\s*#/.test(line)) return
    const m = LINE.exec(line)
    if (m && m[1] !== undefined) out.push({ key: m[1], value: unquote(m[2] ?? ''), line: i })
  })
  return out
}

export function quote(value: string): string {
  if (value === '' || /^[A-Za-z0-9_./:@+-]+$/.test(value)) return value
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`
}

export function isValidKey(key: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key)
}

/** Sets `key` (adds it last when absent); returns the new text. */
export function setKey(text: string, key: string, value: string): string {
  const lines = text === '' ? [] : text.split(/\r?\n/)
  const found = parseEnv(text).find(p => p.key === key)
  const row = `${key}=${quote(value)}`
  if (found) {
    lines[found.line] = /^\s*export\s/.test(lines[found.line] ?? '') ? `export ${row}` : row
    return lines.join('\n')
  }
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  lines.push(row)
  return lines.join('\n') + '\n'
}

export function removeKey(text: string, key: string): string {
  const found = parseEnv(text).find(p => p.key === key)
  if (!found) return text
  const lines = text.split(/\r?\n/)
  lines.splice(found.line, 1)
  return lines.join('\n')
}

export function renameKey(text: string, from: string, to: string): string {
  const found = parseEnv(text).find(p => p.key === from)
  if (!found) return text
  const lines = text.split(/\r?\n/)
  lines[found.line] = (lines[found.line] ?? '').replace(new RegExp(`^(\\s*(?:export\\s+)?)${from.replace(/[.]/g, '\\.')}`), `$1${to}`)
  return lines.join('\n')
}

export function uniqueKey(existing: Set<string>, base: string): string {
  if (!existing.has(base)) return base
  for (let i = 2; ; i++) if (!existing.has(`${base}_${i}`)) return `${base}_${i}`
}

// ── secret detection ───────────────────────────────────────────────

type Detector = { name: string; re: RegExp }

const DETECTORS: Detector[] = [
  { name: 'ANTHROPIC_API_KEY', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'OPENAI_API_KEY', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g },
  { name: 'GITHUB_TOKEN', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/g },
  { name: 'AWS_ACCESS_KEY_ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'SLACK_TOKEN', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { name: 'GOOGLE_API_KEY', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { name: 'STRIPE_SECRET_KEY', re: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{20,}/g },
  { name: 'HUGGINGFACE_TOKEN', re: /\bhf_[A-Za-z0-9]{30,}/g },
  { name: 'GITLAB_TOKEN', re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { name: 'NPM_TOKEN', re: /\bnpm_[A-Za-z0-9]{36}/g },
  { name: 'SENDGRID_API_KEY', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g },
]

// NAME=value or NAME: value where NAME looks secret
const NAMED = /\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIALS?|DSN))\s*[=:]\s*["']?([^\s"'`]{8,})["']?/g

export type Found = { value: string; key: string; isNamed: boolean; start: number; end: number }

// A bare token with no known prefix: 24+ chars of [A-Za-z0-9_-], upper, lower
// and digits all present, not a hex hash or UUID, and random-looking.
const GENERIC = /(?<![A-Za-z0-9_\-./])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_\-/])/g

function entropy(text: string): number {
  const counts = new Map<string, number>()
  for (const c of text) counts.set(c, (counts.get(c) ?? 0) + 1)
  let bits = 0
  for (const n of counts.values()) bits -= (n / text.length) * Math.log2(n / text.length)
  return bits
}

// Pure hex of these lengths is usually a hash (git SHA-1, SHA-256), not a key.
const HASH_LENGTHS = new Set([40, 64])

export function isRandomToken(token: string): boolean {
  // one-case letters + digits (hex or base36 keys): 32+ chars, no separators
  if (!/[a-z]/.test(token) || !/[A-Z]/.test(token)) {
    if (token.length < 32 || !/^[a-z0-9]+$|^[A-Z0-9]+$/.test(token)) return false
    if (!/[0-9]/.test(token) || !/[A-Za-z]/.test(token)) return false
    if (/^[0-9a-fA-F]+$/.test(token) && HASH_LENGTHS.has(token.length)) return false
    return entropy(token) >= 3.0
  }
  if (!/[0-9]/.test(token)) return false
  if (/^[0-9a-fA-F-]+$/.test(token)) return false
  if (/^[A-Za-z]+(?:[_-][A-Za-z0-9]+)+$/.test(token) && !/[0-9][A-Za-z]|[A-Za-z][0-9]/.test(token.replace(/[_-]/g, ''))) return false
  return entropy(token) >= 3.5
}

// ── gitleaks rules ─────────────────────────────────────────────────

type Allow = { target: string; res: RegExp[]; stopwords: string[] }
type Rule = { id: string; re: RegExp; keywords: string[]; entropy: number; secretGroup: number; allow: Allow[] }

function compile(source: string, flags: string): RegExp | null {
  try {
    return new RegExp(source, flags)
  } catch {
    return null
  }
}

const RULES: Rule[] = GITLEAKS_RULES.flatMap(raw => {
  const re = compile(raw.regex, 'gd')
  if (!re) return []
  const allow = raw.allow.map(a => ({
    target: a.target,
    res: a.regexes.map(x => compile(x, '')).filter((x): x is RegExp => x !== null),
    stopwords: a.stopwords,
  }))
  return [{ id: raw.id, re, keywords: raw.keywords, entropy: raw.entropy, secretGroup: raw.secretGroup, allow }]
})
const GLOBAL_RES = GITLEAKS_GLOBAL_REGEXES.map(x => compile(x, '')).filter((x): x is RegExp => x !== null)

export const ruleCount = (): number => RULES.length

/** The env key a rule's id suggests: github-pat → GITHUB_PAT. */
export function keyForRule(id: string): string {
  if (id === 'generic-api-key') return 'API_KEY'
  const key = id.toUpperCase().replace(/[^A-Z0-9]+/g, '_')
  return /^[0-9]/.test(key) ? `KEY_${key}` : key
}

function lineAround(text: string, start: number, end: number): string {
  const from = text.lastIndexOf('\n', start - 1) + 1
  const to = text.indexOf('\n', end)
  return text.slice(from, to < 0 ? text.length : to)
}

function isAllowed(rule: Rule, secret: string, match: string, line: string): boolean {
  const lower = secret.toLowerCase()
  if (GLOBAL_RES.some(re => re.test(secret))) return true
  if (GITLEAKS_GLOBAL_STOPWORDS.some(w => lower.includes(w))) return true
  for (const a of rule.allow) {
    const target = a.target === 'match' ? match : a.target === 'line' ? line : secret
    if (a.res.some(re => re.test(target))) return true
    if (a.stopwords.some(w => lower.includes(w))) return true
  }
  return false
}

/** Runs gitleaks rules as gitleaks does: keywords prefilter, secret group, entropy, allowlists. */
function gitleaksMatches(text: string, isGeneric: boolean): Found[] {
  const lowerText = text.toLowerCase()
  const out: Found[] = []
  for (const rule of RULES) {
    if (rule.id.startsWith('generic') !== isGeneric) continue
    if (rule.keywords.length > 0 && !rule.keywords.some(k => lowerText.includes(k))) continue
    rule.re.lastIndex = 0
    for (const m of text.matchAll(rule.re)) {
      let group = rule.secretGroup
      if (group === 0) for (let g = 1; g < m.length; g++) if (m[g]) { group = g; break }
      const secret = m[group]
      const span = m.indices?.[group]
      if (!secret || !span) continue
      if (rule.entropy > 0) {
        if (entropy(secret) <= rule.entropy) continue
        if (rule.id.startsWith('generic') && !/[0-9]/.test(secret)) continue
      }
      if (isAllowed(rule, secret, m[0], lineAround(text, span[0], span[1]))) continue
      out.push({ value: secret, key: keyForRule(rule.id), isNamed: false, start: span[0], end: span[1] })
    }
  }
  return out
}

// Words that mark a hand-made fake value when they stand as their own segment
// (sk-test-..., fake_token, dummy-key). Stripe's sk_test_/rk_test_ keys are
// real secrets, so they keep being reported.
const PLACEHOLDER_WORDS = new Set(['test', 'testing', 'fake', 'dummy', 'mock', 'example', 'sample', 'placeholder'])

export function isPlaceholder(value: string): boolean {
  if (/^[sr]k_test_/.test(value)) return false
  return value.split(/[^A-Za-z0-9]+/).some(s => PLACEHOLDER_WORDS.has(s.toLowerCase()))
}

export function findSecrets(text: string): Found[] {
  const found: Found[] = []
  const overlaps = (s: number, e: number) => found.some(f => s < f.end && e > f.start)
  const add = (f: Found) => {
    if (!isPlaceholder(f.value) && !overlaps(f.start, f.end)) found.push(f)
  }

  // 1. NAME=value: the user's own name wins
  for (const m of text.matchAll(NAMED)) {
    const key = m[1] ?? ''
    const value = m[2] ?? ''
    const start = (m.index ?? 0) + m[0].indexOf(value, key.length)
    add({ value, key, isNamed: true, start, end: start + value.length })
  }
  // 2. gitleaks provider rules
  for (const f of gitleaksMatches(text, false)) add(f)
  // 3. looser prefixes for keys gitleaks' exact lengths miss
  for (const d of DETECTORS) {
    for (const m of text.matchAll(d.re)) {
      const start = m.index ?? 0
      if (/EXAMPLE$/.test(m[0]) || GLOBAL_RES.some(re => re.test(m[0]))) continue // docs' sample keys
      add({ value: m[0], key: d.name, isNamed: false, start, end: start + m[0].length })
    }
  }
  // 4. gitleaks generic-api-key (keyword = value)
  for (const f of gitleaksMatches(text, true)) add(f)
  // 5. bare random-looking tokens
  for (const m of text.matchAll(GENERIC)) {
    const start = m.index ?? 0
    if (isRandomToken(m[0])) add({ value: m[0], key: 'API_KEY', isNamed: false, start, end: start + m[0].length })
  }
  return found.sort((a, b) => a.start - b.start)
}

/**
 * The stricter set for source files, where hashes, fixtures and long
 * identifiers abound: gitleaks' rules and the known prefixes only, as gitleaks
 * itself scans code. No NAME=value guess and no bare random-token guess.
 */
export function findSecretsInCode(text: string): Found[] {
  const found: Found[] = []
  const add = (f: Found) => {
    if (!isPlaceholder(f.value) && !found.some(g => f.start < g.end && f.end > g.start)) found.push(f)
  }
  for (const f of gitleaksMatches(text, false)) add(f)
  for (const d of DETECTORS) {
    for (const m of text.matchAll(d.re)) {
      const start = m.index ?? 0
      if (/EXAMPLE$/.test(m[0]) || GLOBAL_RES.some(re => re.test(m[0]))) continue
      add({ value: m[0], key: d.name, isNamed: false, start, end: start + m[0].length })
    }
  }
  for (const f of gitleaksMatches(text, true)) add(f)
  return found.sort((a, b) => a.start - b.start)
}

/** 1-based line of a character offset. */
export function lineOf(text: string, offset: number): number {
  let line = 1
  for (let i = text.indexOf('\n'); i >= 0 && i < offset; i = text.indexOf('\n', i + 1)) line++
  return line
}

/** Files a code scan skips: binaries, lockfiles, minified and generated output. */
export function isScannableCode(path: string): boolean {
  const name = baseOf(path).toLowerCase()
  if (/(?:^|[.-])lock$|\.lock$|^package-lock\.json$|^pnpm-lock\.yaml$|^yarn\.lock$|^go\.sum$|^cargo\.lock$|^poetry\.lock$|^composer\.lock$/.test(name)) return false
  if (/\.min\.(?:js|css)$|\.map$|\.snap$/.test(name)) return false
  return !/\.(?:png|jpe?g|gif|webp|ico|icns|bmp|tiff?|svg|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|o|a|so|dylib|dll|exe|bin|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|wav|ogg|flac|psd|sketch|fig|db|sqlite3?|parquet|pyc|pkl|npy|onnx|pt|ckpt)$/.test(name)
}

export function dirOf(path: string): string {
  const i = path.lastIndexOf('/')
  return i < 0 ? '' : path.slice(0, i)
}

export function baseOf(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1)
}
