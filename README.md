# env-manager

A Claude Code mod that keeps local `.env` files under control and keeps secrets out of prompts, source files and commits.

- **Env file tree** (`/env`): every `.env` / `.env.*` file under the project as a folder tree, values masked to their first 5 characters, gitignore and git-tracking status per file
- **File actions**: add, edit, copy (to clipboard), delete keys; create and duplicate env files (a duplicate named `.example` gets empty values); add to `.gitignore` or untrack with one key
- **Prompt interception**: a key pasted into a prompt is moved into the default env file before the model sees it; Claude gets `[env:.env#KEY]` and suggests key names that fit the context
- **Write guard**: when Claude writes a key into a source file, the write is refused, the key moves into the env file and Claude is told to read it from the environment
- **Hardcoded secret scan**: project files are scanned with gitleaks' 217 rules; `gitleaks:allow` (or `env-manager:allow`) on a line skips it, `env-manager:ignore-file` near the top skips the file
- **gitleaks history scan** (optional): runs the `gitleaks` binary over the commit history, keeps each run's result per repository
- **Leak warnings**: a line above the prompt and toasts when an env file is not gitignored, is tracked by git, or a key is hardcoded

## Install

At the prompt of a Claude Code terminal session:

```
/plugin install env-manager --marketplace obov/claude-mod-env-manager
```

Answer `y` to add the marketplace, then pick a scope (user is first). From a shell:

```
claude plugin install env-manager --marketplace obov/claude-mod-env-manager
```

In the desktop app, where `/plugin` does not run: click + next to the prompt box, then Plugins, Add marketplace with `obov/claude-mod-env-manager`, then Add plugin.

Optional, for the history scan:

```
brew install gitleaks
```

## Use

`/env` opens the pane; `/env scan` prints the status as text.

| Key | Where | Does |
| --- | --- | --- |
| `↑` `↓` / `j` `k` | anywhere | move |
| `⏎` `→` `←` | folder, file | open / close |
| `n` | anywhere | new env file in the selected folder |
| `a` `d` | file | add key, duplicate file |
| `i` `u` | file | add to `.gitignore`, untrack from git |
| `c` `e` `x` | key | copy value, edit, delete |
| `r` | anywhere | rescan |
| `s` | anywhere | settings page |

Keys typed with the Korean (두벌식) input source on act as their Latin keys.

## Settings

On the pane's settings page (`s`), or in `/config`:

| Field | Default | Meaning |
| --- | --- | --- |
| `patterns` | `.env .env.*` | file name globs to track |
| `defaultFile` | `.env` | where intercepted keys go |
| `intercept` | `on` | move keys out of prompts |
| `guardWrites` | `on` | refuse Claude's writes that hardcode a key |
| `scanFiles` | `on` | scan project files for hardcoded keys |
| `gitleaks` | `manual` | `off`, `manual` (settings page), `auto` (session start when HEAD moved) |
| `maxDepth` | `5` | folder depth scanned |
| `checkMinutes` | `10` | minimum minutes between rescans at the end of a turn |
| `renamePrompt` | built in | what Claude is told after a key is intercepted; `{file}` `{path}` `{stored}` `{keys}` `{tool}` |

## Develop

```
claude --plugin-dir .
claude plugin validate .
claude plugin test .
python3 scripts/gen-rules.py   # regenerate hooks/rules.ts from gitleaks master
```

Test keys in `tests/` are assembled at run time (`'ghp' + '_…'`) so secret scanners do not flag the repository.

## License

MIT. `hooks/rules.ts` is generated from [gitleaks](https://github.com/gitleaks/gitleaks)' default configuration (MIT, Copyright (c) 2019 Zachary Rice).
