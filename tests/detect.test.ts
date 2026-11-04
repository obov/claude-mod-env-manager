import { expect, test } from 'claude-code/testing'

import { findSecrets, ruleCount } from '../hooks/env'

const caught = (token: string) => findSecrets(`x ${token} y`).length === 1

test('bare keys are caught by shape; hashes, UUIDs and words are not', async () => {
  expect(caught('8b60b84b8071b128e96f9be74fc5a2098767b7ea8df5')).toBe(true) // hex 44
  expect(caught('a3f9c2e17b4d58e06c1f92ab7d3e4c05')).toBe(true) // hex 32
  expect(caught('k3j9x2m8q7w1z5r4t6y0p2l8n3v7b1c9d5f4')).toBe(true) // base36
  expect(caught('fc4bXMa3cc4RqS682b2e6225640a4Dgzp')).toBe(true) // mixed 34
  expect(caught('e83c5163316f89bfbde7d9ab23ca2e25604af290')).toBe(false) // git sha
  expect(caught('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')).toBe(false) // sha256
  expect(caught('123e4567-e89b-12d3-a456-426614174000')).toBe(false) // uuid
  expect(caught('handle_prompt_submit_for_user_2024')).toBe(false)
})

test('every gitleaks rule compiles in the mod runtime', async () => {
  expect(ruleCount()).toBe(217)
})

test('gitleaks provider rules name the key after the provider', async () => {
  const keyOf = (text: string) => findSecrets(text).map(f => f.key).join(',')
  expect(keyOf('ghp' + '_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5')).toBe('GITHUB_PAT')
  expect(keyOf('AKI' + 'AZ7Q3LMN4PRST6UVW')).toBe('AWS_ACCESS_TOKEN')
  expect(keyOf('xox' + 'b-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX')).toBe('SLACK_BOT_TOKEN')
  expect(keyOf('glp' + 'at-aB3dE5fG7hJ9kL1mN3pQ')).toBe('GITLAB_PAT')
  expect(keyOf('my token: Xk29dLq0pZ81')).toBe('API_KEY') // gitleaks:allow (test fixture)
  expect(keyOf('const apiKey = process.env.API_KEY')).toBe('')
  expect(keyOf('password = "changeme"')).toBe('')
  expect(keyOf('AKI' + 'AIOSFODNN7EXAMPLE')).toBe('')
})
