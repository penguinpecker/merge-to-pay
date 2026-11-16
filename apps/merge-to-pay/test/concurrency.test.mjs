// Concurrency & in-lock cache recheck: ensures queued requests waiting on the prover mutex
// recheck the PR cache upon acquiring the lock, coalescing onto the stored result without
// duplicate proving or consuming extra daily slots. Offline with stubbed dependencies.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { run, RunError } from '../src/run.mjs'
import { withLock } from '../src/prover.mjs'
import * as store from '../src/store.mjs'

const tempDir = mkdtempSync(join(tmpdir(), 'm2p-concurrency-'))
process.env.DATA_DIR = tempDir
process.env.PROVER_WAIT_MS = '5000'
delete process.env.KURIER_API_KEY
delete process.env.ESCROW_ADDRESS

const origFetch = globalThis.fetch
before(() => {
  globalThis.fetch = async (url) => {
    return {
      ok: true,
      status: 200,
      json: async () => ({
        pull_request: { merged_at: new Date().toISOString() },
        body: 'verity-payout: #1 0x1111111111111111111111111111111111111111',
      }),
    }
  }
})

after(() => {
  globalThis.fetch = origFetch
  try { rmSync(tempDir, { recursive: true, force: true }) } catch {}
})

beforeEach(() => {
  for (const k of store.list('prs')) store.remove('prs', k)
  for (const k of store.list('daily')) store.remove('daily', k)
})

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const fakeMergedRecord = (repo, pr) => ({
  decision: 'PAY',
  reason: 'BOUNTY_OPEN',
  facts: { repo, pr, merged: true, issue: 1, payee: '0x1111111111111111111111111111111111111111' },
  provedAt: new Date().toISOString(),
})

test('concurrent waiter returns cached merged record once stored by first run', async () => {
  let release
  const held = withLock(() => new Promise((r) => { release = r }), 10_000)

  const ref = 'testowner/testrepo#101'
  const p = run(ref)
  await sleep(25)

  const record = fakeMergedRecord('testowner/testrepo', 101)
  store.write('prs', store.prKey({ repo: 'testowner/testrepo', pr: 101 }), record)

  release()
  await held

  const res = await p
  assert.equal(res.cached, true)
  assert.equal(res.decision, 'PAY')
  assert.equal(res.facts.pr, 101)
})

test('concurrent waiter does not consume another daily slot after cache is stored', async () => {
  let release
  const held = withLock(() => new Promise((r) => { release = r }), 10_000)

  const ref = 'testowner/testrepo#102'
  const p = run(ref)
  await sleep(25)

  const record = fakeMergedRecord('testowner/testrepo', 102)
  store.write('prs', store.prKey({ repo: 'testowner/testrepo', pr: 102 }), record)

  release()
  await held

  const res = await p
  assert.equal(res.cached, true)
  assert.equal(store.dailyCount(), 0, 'no daily slot should be reserved for cached waiter')
})

test('two concurrent requests coalesce on persisted result without duplicate proof work', async () => {
  let release
  const held = withLock(() => new Promise((r) => { release = r }), 10_000)

  const ref = 'testowner/testrepo#103'
  const p1 = run(ref)
  const p2 = run(ref)
  await sleep(25)

  const record = fakeMergedRecord('testowner/testrepo', 103)
  store.write('prs', store.prKey({ repo: 'testowner/testrepo', pr: 103 }), record)

  release()
  await held

  const [r1, r2] = await Promise.all([p1, p2])
  assert.equal(r1.cached, true)
  assert.equal(r2.cached, true)
  assert.equal(store.dailyCount(), 0, 'daily cap untouched for both cached waiters')
})

test('unexpired NOT_MERGED record stored during wait is returned as cached', async () => {
  let release
  const held = withLock(() => new Promise((r) => { release = r }), 10_000)

  const ref = 'testowner/testrepo#104'
  const p = run(ref)
  await sleep(25)

  const notMergedRecord = {
    decision: 'DECLINE',
    reason: 'NOT_MERGED',
    facts: { repo: 'testowner/testrepo', pr: 104, merged: false, issue: null, payee: null },
    expiresAt: Date.now() + 600_000,
  }
  store.write('prs', store.prKey({ repo: 'testowner/testrepo', pr: 104 }), notMergedRecord)

  release()
  await held

  const res = await p
  assert.equal(res.cached, true)
  assert.equal(res.reason, 'NOT_MERGED')
  assert.equal(store.dailyCount(), 0)
})

test('preserves retry=1 and expiration behavior during in-lock recheck', async () => {
  // Case A: retry=1 ignores unexpired NOT_MERGED and proceeds to fresh run
  let releaseA
  const heldA = withLock(() => new Promise((r) => { releaseA = r }), 10_000)

  const refA = 'testowner/testrepo#105'
  const pA = run(refA, { retry: true })
  await sleep(25)

  const notMergedRecord = {
    decision: 'DECLINE',
    reason: 'NOT_MERGED',
    facts: { repo: 'testowner/testrepo', pr: 105, merged: false, issue: null, payee: null },
    expiresAt: Date.now() + 600_000,
  }
  store.write('prs', store.prKey({ repo: 'testowner/testrepo', pr: 105 }), notMergedRecord)

  releaseA()
  await heldA

  // retry=1 bypasses NOT_MERGED, so it attempts fresh run (takes slot, then fails at zktls offline)
  await assert.rejects(pA, (err) => err instanceof RunError && err.status === 502 && err.reason === 'ATTESTOR')
  assert.equal(store.dailyCount(), 1, 'fresh run attempted and reserved a slot')

  // Case B: expired record is ignored and proceeds to fresh run
  let releaseB
  const heldB = withLock(() => new Promise((r) => { releaseB = r }), 10_000)

  const refB = 'testowner/testrepo#106'
  const pB = run(refB)
  await sleep(25)

  const expiredRecord = {
    decision: 'DECLINE',
    reason: 'NOT_MERGED',
    facts: { repo: 'testowner/testrepo', pr: 106, merged: false, issue: null, payee: null },
    expiresAt: Date.now() - 1000,
  }
  store.write('prs', store.prKey({ repo: 'testowner/testrepo', pr: 106 }), expiredRecord)

  releaseB()
  await heldB

  await assert.rejects(pB, (err) => err instanceof RunError && err.status === 502 && err.reason === 'ATTESTOR')
  assert.equal(store.dailyCount(), 2, 'fresh run attempted and reserved another slot')
})
