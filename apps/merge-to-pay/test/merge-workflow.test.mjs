import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'

const endpoint = 'https://agent-production-8f9c2448.up.railway.app/api/agent'
const workflow = readFileSync(new URL('../../../.github/workflows/merge-to-pay.yml', import.meta.url), 'utf8')
const run = workflow.match(/        run: \|\n([\s\S]+)$/)?.[1].replace(/^          /gm, '')

async function notify(responses, repository = 'penguinpecker/merge-to-pay', transportFailures = 0) {
  assert.ok(run, 'the workflow must contain a shell step')
  const dir = mkdtempSync(join(tmpdir(), 'm2p-workflow-'))
  const requests = []
  const server = createServer(async (req, res) => {
    let body = ''
    for await (const chunk of req) body += chunk
    requests.push({ url: req.url, method: req.method, contentType: req.headers['content-type'], body })
    const response = responses[Math.min(requests.length - 1, responses.length - 1)]
    res.writeHead(response.status ?? 200, { 'content-type': 'application/json' })
    res.end(typeof response.body === 'string' ? response.body : JSON.stringify(response.body))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    // Redirect only the workflow's fixed URL to the local fixture server. The real curl still
    // performs HTTP, writes its response file and returns its actual HTTP/transport status.
    writeFileSync(join(dir, 'curl'), `#!${process.execPath}
const fs = require('node:fs')
const cp = require('node:child_process')
const args = process.argv.slice(2)
const url = args.at(-1)
if (url !== process.env.ENDPOINT && url !== process.env.ENDPOINT + '?retry=1') process.exit(99)
const counter = process.env.COUNTER
const attempt = fs.existsSync(counter) ? Number(fs.readFileSync(counter, 'utf8')) : 0
fs.writeFileSync(counter, String(attempt + 1))
if (attempt < Number(process.env.TRANSPORT_FAILURES)) process.exit(7)
args[args.length - 1] = process.env.LOCAL_URL + url.slice(process.env.ENDPOINT.length)
const result = cp.spawnSync('/usr/bin/curl', args, { stdio: 'inherit' })
process.exit(result.status ?? 1)
`, { mode: 0o700 })
    // Exercise retry control flow without spending production backoff time in unit tests.
    writeFileSync(join(dir, 'sleep'), '#!/bin/sh\nexit 0\n', { mode: 0o700 })
    const result = await new Promise((resolve, reject) => {
      const child = spawn('bash', ['-e', '-o', 'pipefail', '-c', run], {
        env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, ENDPOINT: endpoint,
          LOCAL_URL: `http://127.0.0.1:${server.address().port}/api/agent`, COUNTER: join(dir, 'attempt'),
          TRANSPORT_FAILURES: String(transportFailures), REPOSITORY: repository, PR_NUMBER: '42' },
      })
      let stdout = '', stderr = ''
      child.stdout.on('data', (data) => { stdout += data })
      child.stderr.on('data', (data) => { stderr += data })
      child.on('error', reject)
      child.on('close', (status) => resolve({ status, stdout, stderr }))
    })
    return { ...result, requests, attempts: Number(readFileSync(join(dir, 'attempt'), 'utf8')) }
  } finally {
    await new Promise((resolve) => server.close(resolve))
    rmSync(dir, { recursive: true, force: true })
  }
}

const pay = { decision: 'PAY', reason: 'BOUNTY_OPEN' }
const notMerged = { decision: 'DECLINE', reason: 'NOT_MERGED' }
const busy = { status: 503, body: { decision: 'ERROR', reason: 'BUSY' } }

test('workflow only notifies on merged PR closure, without token permissions or checkout', () => {
  assert.match(workflow, /on:\n  pull_request:\n    types: \[closed\]/)
  assert.match(workflow, /if: github\.event\.pull_request\.merged == true/)
  assert.match(workflow, /permissions: \{\}/)
  assert.doesNotMatch(workflow, /uses:|secrets\.|pull_request_target|github\.event\.pull_request\.(title|body)/)
})

test('posts only the repository and PR number, using POST JSON', async () => {
  const result = await notify([{ body: pay }])
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.requests, [{ url: '/api/agent', method: 'POST', contentType: 'application/json',
    body: '{"pr":"penguinpecker/merge-to-pay#42"}' }])
  assert.deepEqual(JSON.parse(result.stdout), pay)
})

test('503 BUSY then PAY logs only the final response', async () => {
  const result = await notify([busy, { body: pay }])
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.requests.length, 2)
  assert.deepEqual(JSON.parse(result.stdout), pay)
})

test('NOT_MERGED retries with the explicit cache-bypass parameter', async () => {
  const result = await notify([{ body: notMerged }, { body: pay }])
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.requests.map((r) => r.url), ['/api/agent', '/api/agent?retry=1'])
  assert.deepEqual(JSON.parse(result.stdout), pay)
})

test('transport errors are retried within the fixed attempt limit', async () => {
  const result = await notify([{ body: pay }], undefined, 1)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.attempts, 2)
})

test('a permanent decline is logged once without another proof request', async () => {
  const decline = { decision: 'DECLINE', reason: 'NO_BOUNTY' }
  const result = await notify([{ body: decline }])
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.requests.length, 1)
  assert.deepEqual(JSON.parse(result.stdout), decline)
})

test('metadata is serialized as JSON and never evaluated as shell code', async () => {
  const repository = 'owner/"quoted"; $(exit 99)'
  const result = await notify([{ body: pay }], repository)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(JSON.parse(result.requests[0].body), { pr: `${repository}#42` })
})

test('multiline response fields remain escaped in one JSON log line', async () => {
  const response = { decision: 'DECLINE', reason: 'NO_BOUNTY\n::warning::not a workflow command' }
  const result = await notify([{ body: response }])
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim().split('\n').length, 1)
  assert.deepEqual(JSON.parse(result.stdout), response)
})

for (const response of [busy, { body: notMerged }, { status: 500, body: { decision: 'ERROR', reason: 'PROOF_FAILED' } },
  { body: 'not JSON' }, { body: '{}' }, { body: '{"decision":"PAY"}' },
  { body: '{"decision":null,"reason":"BOUNTY_OPEN"}' }, { body: '{"decision":"PAY","reason":"OK"}{}' }]) {
  test(`fails on errors, exhausted retries, or an invalid response: ${JSON.stringify(response)}`, async () => {
    const result = await notify([response])
    assert.notEqual(result.status, 0)
    assert.ok(result.attempts <= 3)
  })
}
