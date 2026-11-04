#!/usr/bin/env python3
"""Regenerate hooks/rules.ts from gitleaks' default config.

    python3 scripts/gen-rules.py            # fetch gitleaks master
    python3 scripts/gen-rules.py path.toml  # from a local copy

Go (RE2) regexes are rewritten for JavaScript: case-insensitive parts become
[aA] classes, (?s) dots [\\s\\S], braces escaped. Rules scoped to a file path
are left out. Sample keys in allowlists are written AI[z]a... so secret
scanners do not flag the generated file. Check after: claude plugin test .
"""
import json, os, sys, tomllib, urllib.request

def other(c):
    return c.swapcase() if c.isalpha() and c.isascii() else None

POSIX = {'alnum': 'a-zA-Z0-9', 'alpha': 'a-zA-Z', 'digit': '0-9', 'upper': 'A-Z', 'lower': 'a-z', 'space': r'\s', 'xdigit': '0-9a-fA-F', 'word': r'\w', 'punct': r'!-\/:-@\[-`{-~'}

def convert(src):
    out = []
    i = 0
    n = len(src)
    # stack entries: (ci, dotall) for each open group
    stack = [[False, False]]
    def mode(): return stack[-1]
    while i < n:
        c = src[i]
        if c == '\\':
            nx = src[i + 1]
            if nx == 'z': out.append('$'); i += 2; continue
            if nx == 'A': out.append('^'); i += 2; continue
            if nx == 'x':
                out.append(src[i:i + 4]); i += 4; continue
            out.append(src[i:i + 2]); i += 2; continue
        if c == '[':
            j = i + 1
            neg = ''
            if j < n and src[j] == '^': neg = '^'; j += 1
            items = []
            first = True
            while True:
                ch = src[j]
                if ch == ']' and not first: break
                first = False
                if src.startswith('[:', j):
                    end = src.index(':]', j)
                    items.append(POSIX[src[j + 2:end]]); j = end + 2; continue
                if ch == '\\':
                    esc = src[j:j + 2]
                    if src[j + 1] == 'x': esc = src[j:j + 4]
                    j += len(esc)
                    # range from escape?
                    items.append(esc); continue
                if ch == ']': items.append('\\]'); j += 1; continue
                if ch == '[': items.append('\\['); j += 1; continue
                # range
                if j + 2 < n and src[j + 1] == '-' and src[j + 2] != ']':
                    lo, hi = ch, src[j + 2]
                    if hi == '\\':
                        hi = src[j + 2:j + 4]; j += 4
                        items.append(f'{lo}-{hi}'); continue
                    items.append(f'{lo}-{hi}')
                    if mode()[0] and lo.isalpha() and hi.isalpha() and lo.isascii() and hi.isascii() and lo.islower() == hi.islower():
                        items.append(f'{lo.swapcase()}-{hi.swapcase()}')
                    j += 3; continue
                items.append(ch)
                if mode()[0] and other(ch): items.append(other(ch))
                j += 1
            out.append('[' + neg + ''.join(items) + ']')
            i = j + 1; continue
        if c == '(':
            if src.startswith('(?i)', i): mode()[0] = True; i += 4; continue
            if src.startswith('(?s)', i): mode()[1] = True; i += 4; continue
            if src.startswith('(?i:', i): stack.append([True, mode()[1]]); out.append('(?:'); i += 4; continue
            if src.startswith('(?-i:', i): stack.append([False, mode()[1]]); out.append('(?:'); i += 5; continue
            if src.startswith('(?s:', i): stack.append([mode()[0], True]); out.append('(?:'); i += 4; continue
            if src.startswith('(?P<', i): stack.append(list(mode())); out.append('(?<'); i += 4; continue
            if src.startswith('(?', i) and not src.startswith('(?:', i) and not src.startswith('(?<', i) and not src.startswith('(?=', i) and not src.startswith('(?!', i):
                raise ValueError('flag group at ' + src[i:i + 8])
            stack.append(list(mode()))
            if src.startswith('(?:', i): out.append('(?:'); i += 3
            else: out.append('('); i += 1
            continue
        if c == ')':
            stack.pop(); out.append(')'); i += 1; continue
        if c == '.' and mode()[1]: out.append('[\\s\\S]'); i += 1; continue
        if c == '{':
            # quantifier {n}, {n,}, {n,m} stays; literal brace escaped
            k = src.find('}', i)
            body = src[i + 1:k] if k > 0 else ''
            import re as _re
            if k > 0 and _re.fullmatch(r'\d+(,\d*)?', body):
                out.append(src[i:k + 1]); i = k + 1; continue
            out.append('\\{'); i += 1; continue
        if c == '}': out.append('\\}'); i += 1; continue
        if mode()[0] and other(c):
            out.append(f'[{c}{other(c)}]'); i += 1; continue
        out.append(c); i += 1
    return ''.join(out)


URL = 'https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml'
API = 'https://api.github.com/repos/gitleaks/gitleaks/commits/master'


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, '..', 'hooks', 'rules.ts')
    if len(sys.argv) > 1:
        raw, rev = open(sys.argv[1], 'rb').read(), 'local copy'
    else:
        raw = urllib.request.urlopen(URL).read()
        rev = 'gitleaks/gitleaks@' + json.load(urllib.request.urlopen(API))['sha'][:12]
    d = tomllib.loads(raw.decode())
    rules = []
    for r in d['rules']:
        if 'regex' not in r or 'path' in r:
            continue
        allows = []
        for a in r.get('allowlists', []):
            if 'paths' in a and (a.get('condition') == 'AND' or (not a.get('regexes') and not a.get('stopwords'))):
                continue
            allows.append({
                'target': a.get('regexTarget', 'secret'),
                'regexes': [convert(x).replace('AIza', 'AI[z]a') for x in a.get('regexes', [])],
                'stopwords': [s.lower() for s in a.get('stopwords', [])],
            })
        rules.append({'id': r['id'], 'regex': convert(r['regex']), 'keywords': [k.lower() for k in r.get('keywords', [])],
                      'entropy': r.get('entropy', 0), 'secretGroup': r.get('secretGroup', 0), 'allow': allows})
    glob = d['allowlist']
    head = HEAD.replace('{rev}', rev)
    body = 'export const GITLEAKS_RULES: RawRule[] = ' + json.dumps(rules, ensure_ascii=False, indent=0) + '\n\n'
    body += 'export const GITLEAKS_GLOBAL_REGEXES: string[] = ' + json.dumps([convert(x) for x in glob.get('regexes', [])], ensure_ascii=False) + '\n\n'
    body += 'export const GITLEAKS_GLOBAL_STOPWORDS: string[] = ' + json.dumps([s.lower() for s in glob.get('stopwords', [])], ensure_ascii=False) + '\n'
    open(out_path, 'w').write(head + body)
    print(f'{len(rules)} rules -> {os.path.normpath(out_path)}')


HEAD = '// env-manager:ignore-file (regex sources, not secrets)\n// Generated from gitleaks\' default config (config/gitleaks.toml at\n// {rev}), its Go regexes rewritten for JavaScript:\n// case-insensitive parts expanded to [aA] classes, (?s) dots as [\\s\\S].\n// Rules scoped to a file path (.tf, nuget.config, k8s yaml) are left out:\n// a prompt has no path. Sample keys in allowlists are written AI[z]a... so\n// secret scanners do not flag this file. Do not edit by hand: regenerate.\n//\n// gitleaks is MIT licensed:\n// MIT License\n// Copyright (c) 2019 Zachary Rice\n// Permission is hereby granted, free of charge, to any person obtaining a copy\n// of this software and associated documentation files (the "Software"), to deal\n// in the Software without restriction, including without limitation the rights\n// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n// copies of the Software, and to permit persons to whom the Software is\n// furnished to do so, subject to the following conditions:\n// The above copyright notice and this permission notice shall be included in\n// all copies or substantial portions of the Software.\n// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n// SOFTWARE.\n\nexport type RawAllow = { target: string; regexes: string[]; stopwords: string[] }\nexport type RawRule = { id: string; regex: string; keywords: string[]; entropy: number; secretGroup: number; allow: RawAllow[] }\n\n'

if __name__ == '__main__':
    main()
