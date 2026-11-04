export type EnvEntry = {
  key: string
  masked: string
}

export type EnvFile = {
  /** path relative to the scan root, `/` separated */
  path: string
  /** gitignored; null outside a git repo */
  isIgnored: boolean | null
  /** tracked by git (a leak even when ignored) */
  isTracked: boolean
  /** .example / .sample / .template: meant to be committed */
  isTemplate: boolean
  entries: EnvEntry[]
}

export type EnvScan = {
  root: string
  gitRoot: string | null
  files: EnvFile[]
  /** folders below the root that were scanned, relative */
  dirs: string[]
  scannedAt: number
}

export type EnvMode =
  | { kind: 'new'; dir: string }
  | { kind: 'add'; file: string }
  | { kind: 'edit'; file: string; key: string }
  | { kind: 'dup'; file: string }
  | { kind: 'setting'; field: string }

export type EnvUi = {
  /** env files whose keys are shown */
  open: string[]
  /** folders the person opened or closed (otherwise open when they hold env files) */
  dirOpen: string[]
  dirClosed: string[]
  /** which page the pane shows */
  view: 'tree' | 'settings'
  /** id of the selected row on the tree page */
  cursor: string
  /** id of the selected row on the settings page */
  setCursor: string
  /** the input shown in the footer, if any */
  mode: EnvMode | null
  message: string
}

/** One row of the tree, as the rows client draws it. */
export type EnvSeg = { t: string; c?: string; b?: boolean; dim?: boolean }
export type EnvRow = { id: string; left: EnvSeg[]; right: EnvSeg[] }
export type EnvRowsProps = { rows: EnvRow[]; active: string; activeBg: string; hoverBg: string }

/** A key written into a source file (not an env file). */
export type CodeFinding = { path: string; line: number; rule: string; masked: string }

export type CodeScan = {
  status: 'idle' | 'running' | 'done'
  files: number
  findings: CodeFinding[]
  at: number
}

/** One finding of `gitleaks git` (values redacted by gitleaks). */
export type HistoryFinding = { rule: string; file: string; line: number; commit: string; date: string }

/** What a gitleaks run over the repo's history left, kept per repo in $.store. */
export type GitleaksRecord = {
  ranAt: number
  head: string
  version: string
  count: number
  findings: HistoryFinding[]
  error: string
}

export type GitleaksState = {
  /** `gitleaks version`, '' when not installed, null before the check */
  version: string | null
  running: boolean
  record: GitleaksRecord | null
}

declare module 'claude-code' {
  interface PluginState {
    'env-manager': {
      scan: Shaped<EnvScan | null>
      ui: Shaped<EnvUi>
      hiddenWarning: string
      code: Shaped<CodeScan>
      gitleaks: Shaped<GitleaksState>
    }
  }
}
