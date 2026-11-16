// One PR through the pipeline: parse → stored? → classify (plain HTTPS, refuse-only) → lock → stored? → daily cap →
// zkTLS → circuit proof → decision (escrow read) → Kurier submit → poll to Finalized → durable record.
// Transport failures (attestor, GitHub, Kurier, RPC) are ERROR 502/503, never DECLINE.
// C1(c): a merged PR is proven once; its record is returned for every later request.
import { VerityClient } from '@verity/sdk'
import { hexlify } from 'ethers'
import { createPublicClient, http, keccak256, encodeAbiParameters, parseAbi } from 'viem'
import { base } from 'viem/chains'
import { parsePr, request } from './spec.mjs'
import { proveClaim, withLock, BusyError } from './prover.mjs'
import * as kurier from './kurier.mjs'
import * as store from './store.mjs'
import { decodeAuthToken } from '../scripts/make-auth-token.mjs'
import { release, releaseArgs, relayer } from './settle.mjs'

export class RunError extends Error {
  constructor(status, reason, msg) { super(msg); this.status = status; this.reason = reason }
}
const env = (k, d) => process.env[k] ?? d
const maxMergeAgeS = () => Number(env('MAX_MERGE_AGE_S', 3600))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const addr = (n) => '0x' + n.toString(16).padStart(40, '0')
const LINE_RE = /^verity-payout: #[1-9][0-9]{0,8} 0x[0-9a-fA-F]{40}/

export const STATEMENT = 'An attestor witnessed a TLS session with api.github.com in which GET /repos/{repo}/issues/{pr} returned "merged_at" and the leading "verity-payout: #<issue> 0x<payee>" line of the body. The github_pr circuit checks the attestor signature over that claim and exposes 7 public inputs: attestor, repoKey (keccak256(repo) >> 8), pr, merged, issue, payee, timestamp. zkVerify verifies the UltraHonk proof; the Base escrow pays only against a zkVerify aggregation.'

/** Refuse-only triage from a plain GitHub issue JSON. Unproven: it never grants anything. */
export function classify(json, now = Date.now()) {
  if (!json.pull_request) return { pr: false }
  const mergedAt = json.pull_request.merged_at ?? null
  const hasLine = LINE_RE.test(json.body ?? '')
  const tooOld = Boolean(mergedAt && hasLine && (now - Date.parse(mergedAt)) / 1000 > maxMergeAgeS())
  return { pr: true, mergedAt, hasLine, tooOld }
}

async function fetchIssue({ repo, pr }) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'verity-merge-to-pay', 'x-github-api-version': '2022-11-28' }
  if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  let r
  try { r = await fetch(`https://api.github.com/repos/${repo}/issues/${pr}`, { headers, signal: AbortSignal.timeout(15_000) }) } catch (e) { throw new RunError(502, 'GITHUB', e.message) }
  if (r.status === 404) throw new RunError(422, 'NOT_FOUND', `${repo}#${pr} does not exist`)
  if (!r.ok) throw new RunError(502, 'GITHUB', `GitHub HTTP ${r.status}`)
  return r.json()
}

/** Pure policy over the proven public inputs plus an escrow read ({amount, expiry, minPr, paid, prUsed}, bigint/bool) or undefined. */
export function decide({ merged, issue, pr }, bounty, nowS = Math.floor(Date.now() / 1000)) {
  if (!merged) return ['DECLINE', 'NOT_MERGED']
  if (issue === 0n) return ['DECLINE', 'NO_PAYOUT_LINE']
  if (!bounty) return ['ELIGIBLE', 'NO_ESCROW_CONFIGURED']
  if (bounty.amount === 0n) return ['DECLINE', 'NO_BOUNTY']
  if (bounty.paid) return ['DECLINE', 'BOUNTY_PAID']
  if (bounty.prUsed) return ['DECLINE', 'PR_USED']
  if (BigInt(nowS) > bounty.expiry) return ['DECLINE', 'EXPIRED']
  if (pr < bounty.minPr) return ['DECLINE', 'BELOW_MIN_PR']
  return ['PAY', 'BOUNTY_OPEN']
}

const ABI = parseAbi([
  'function bounties(bytes32 id) view returns (uint256 amount, uint64 expiry, uint64 minPr, bool paid)',
  'function prUsed(bytes32 prKey) view returns (bool)',
])
const id2 = (a, b) => keccak256(encodeAbiParameters([{ type: 'uint256' }, { type: 'uint256' }], [a, b]))

/** Escrow read on Base, or undefined when ESCROW_ADDRESS / BASE_RPC_URL are not set. */
export async function readEscrow({ repoKey, issue, pr }) {
  const address = process.env.ESCROW_ADDRESS
  if (!address || !process.env.BASE_RPC_URL) return undefined
  const client = createPublicClient({ chain: base, transport: http(process.env.BASE_RPC_URL) })
  try {
    const [[amount, expiry, minPr, paid], prUsed] = await Promise.all([
      client.readContract({ address, abi: ABI, functionName: 'bounties', args: [id2(repoKey, issue)] }),
      client.readContract({ address, abi: ABI, functionName: 'prUsed', args: [id2(repoKey, pr)] }),
    ])
    return { amount, expiry, minPr, paid, prUsed }
  } catch (e) { throw new RunError(502, 'RPC', e.shortMessage || e.message) }
}

const authRequest = () => (process.env.ATTESTOR_AUTH_TOKEN ? decodeAuthToken(process.env.ATTESTOR_AUTH_TOKEN.trim()) : undefined)

/** zkTLS proof of the issue endpoint, under our own timeout (M5: the SDK's 3 × 90 s retries can't be configured). */
export async function zktls(slots, { attestorUrl = process.env.VERITY_ATTESTOR_URL, authRequest, timeoutMs = 45_000, onStep } = {}) {
  const client = new VerityClient({ attestorUrl, authRequest, trustedAttestors: process.env.ATTESTOR_ADDRESS ? [process.env.ATTESTOR_ADDRESS] : [] })
  const token = process.env.GITHUB_TOKEN
  let timer
  try {
    const proof = await Promise.race([
      client.prove({ ...request(slots), secretParams: token ? { headers: { Authorization: `Bearer ${token}` } } : undefined, onStep }),
      new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`attestor timeout after ${timeoutMs} ms`)), timeoutMs) }),
    ])
    if (!(await client.verify(proof))) throw new Error('attestor signature invalid or signer not trusted')
    return proof
  } finally { clearTimeout(timer); await client.close() }
}

async function vkHashFor(vkHex) {
  if (process.env.VK_HASH) return process.env.VK_HASH
  const c = store.read('config', 'vk')
  if (c?.vkHex === vkHex) return c.vkHash
  const vkHash = await kurier.registerVk(vkHex)
  store.write('config', 'vk', { vkHex, vkHash })
  return vkHash
}
const kerr = (e) => (e instanceof RunError ? e : new RunError(e.kind === 'network' ? 503 : 502, 'KURIER', e.message))

/** Fold a Kurier job-status JSON into a record. */
export function apply(rec, j) {
  const z = rec.zkverify
  Object.assign(z, { status: j.status, txHash: j.txHash ?? z.txHash, explorer: j.txExplorerUrl ?? z.explorer, statement: j.statement ?? j.aggregationDetails?.leaf ?? z.statement })
  if (z.statement && !z.leafRule) {
    const vk = store.read('config', 'vk')
    z.leafRule = vk ? kurier.matchStatement(vk.vkHex, z.publicInputs, z.vkHash, z.statement)?.name ?? 'NONE' : null
  }
  if (j.aggregationId != null) rec.aggregation.aggregationId = j.aggregationId
  if (j.aggregationDetails) rec.aggregation.details = j.aggregationDetails
  if (kurier.isPublished(j)) Object.assign(rec.aggregation, { status: 'published', txHash: j.aggregationPublished.destinationTxHash })
  else if (j.status === 'Aggregated') rec.aggregation.status = 'aggregated'
  if (j.errorDetails) z.error = j.errorDetails
  return rec
}

/** Stateless re-poll by jobId; the stored record is updated only on a settled status. */
export async function jobUpdate(jobId) {
  let j
  try { j = await kurier.jobStatus(jobId) } catch (e) { throw e.kind === 'input' ? new RunError(400, 'BAD_JOB', e.message) : kerr(e) }
  const ref = store.read('jobs', jobId)
  let record = ref && store.read('prs', ref.key)
  if (record?.zkverify.jobId === jobId && kurier.isSettled(j)) record = store.write('prs', ref.key, apply(record, j))
  return { job: j, record: record ?? null }
}

export const config = () => ({
  attestor: env('ATTESTOR_ADDRESS', null),
  attestorUrl: env('VERITY_ATTESTOR_URL', null),
  vkHash: env('VK_HASH') ?? store.read('config', 'vk')?.vkHash ?? null,
  escrow: env('ESCROW_ADDRESS', null),
  relayer: relayer(),
  chainId: 8453,
  maxMergeAgeS: maxMergeAgeS(),
  daily: { used: store.dailyCount(), cap: store.dailyCap() },
  statement: STATEMENT,
})

const readCached = (key, retry) => {
  const stored = store.read('prs', key)
  if (stored && !(retry && stored.reason === 'NOT_MERGED') && !(stored.expiresAt && stored.expiresAt <= Date.now())) return { ...stored, cached: true }
}

/** The whole pipeline for one PR reference. Resolves to the §8 JSON; rejects with RunError. */
export async function run(ref, { retry = false, onStep = () => {} } = {}) {
  let slots
  try { slots = parsePr(ref) } catch (e) { throw new RunError(400, 'BAD_REF', e.message) }
  const key = store.prKey(slots)
  const cached = readCached(key, retry)
  if (cached) return cached
  onStep('classify')
  const c = classify(await fetchIssue(slots))
  if (!c.pr) throw new RunError(422, 'NOT_A_PR', `${slots.repo}#${slots.pr} is an issue, not a pull request`)
  if (c.tooOld) return { decision: 'DECLINE', reason: 'MERGE_TOO_OLD', facts: { ...slots, merged: true, mergedAt: c.mergedAt }, maxMergeAgeS: maxMergeAgeS() }
  try {
    return await withLock(() => {
      const stored = readCached(key, retry)
      if (stored) return stored
      return fresh(slots, key, { retry, onStep })
    })
  } catch (e) { throw e instanceof BusyError ? new RunError(503, 'BUSY', e.message) : e }
}

async function fresh(slots, key, { retry, onStep }) {
  const stored = readCached(key, retry)
  if (stored) return stored
  if (!store.takeDailySlot()) throw new RunError(429, 'DAILY_CAP', `daily cap of ${store.dailyCap()} fresh runs reached`)
  onStep('zktls')
  let proof
  try { proof = await zktls(slots, { authRequest: authRequest(), onStep: (s) => s?.name && onStep('zktls', s.name) }) } catch (e) { throw new RunError(502, 'ATTESTOR', e.message) }
  onStep('prove')
  let p
  try { p = await proveClaim(proof) } catch (e) { throw new RunError(500, 'PROVER', e.message) }
  const [, repoKey, pr, merged, issue, payee, ts] = p.pubs
  const facts = { repo: slots.repo, pr: Number(pr), merged: merged === 1n, issue: issue ? Number(issue) : null, payee: issue ? addr(payee) : null }
  onStep('escrow')
  const bounty = facts.merged && facts.issue ? await readEscrow({ repoKey, issue, pr }) : undefined
  const [decision, reason] = decide({ merged: facts.merged, issue, pr }, bounty)
  onStep('kurier')
  const chainId = decision === 'PAY' || process.env.AGGREGATE_ALL === '1' ? 8453 : undefined
  let vkHash, jobId
  try {
    vkHash = await vkHashFor(p.vkHex)
    ;({ jobId } = await kurier.submitProof({ proofHex: p.proofHex, pubs: p.pubs, vkHash, chainId }))
  } catch (e) { throw kerr(e) }
  const rec = {
    decision, reason, facts,
    zktls: { attestor: proof.attestor, url: request(slots).url, observedNoEarlierThan: new Date(Number(ts) * 1000).toISOString(), claim: proof.claim,
      signatures: { attestorAddress: proof.signatures.attestorAddress, claimSignature: hexlify(proof.signatures.claimSignature) } },
    zkverify: { jobId, status: 'Queued', txHash: null, explorer: null, statement: null, vkHash, publicInputs: p.pubs.map(kurier.hex32) },
    aggregation: { chainId: chainId ?? null, status: chainId ? 'pending' : null, aggregationId: null },
    payout: { escrow: env('ESCROW_ADDRESS', null), txHash: null, amount: bounty ? bounty.amount.toString() : null },
    provedAt: new Date().toISOString(), timings: p.ms,
  }
  // NOT_MERGED is cached 10 min, and not at all on ?retry=1 (M7); merged results are permanent (C1c).
  const persist = facts.merged || !retry
  if (!facts.merged) rec.expiresAt = Date.now() + 600_000
  const save = () => persist && store.write('prs', key, rec)
  save()
  store.write('jobs', jobId, { key })
  onStep('poll')
  const deadline = Date.now() + Number(env('KURIER_TIMEOUT_S', 180)) * 1000
  while (Date.now() < deadline) {
    await sleep(2000)
    let j
    try { j = await kurier.jobStatus(jobId) } catch (e) { throw kerr(e) }
    if (j.status !== rec.zkverify.status) onStep('kurier', j.status)
    apply(rec, j)
    if (kurier.isFailed(j)) { store.remove('prs', key); throw new RunError(502, 'KURIER_FAILED', JSON.stringify(j.errorDetails ?? j.status)) }
    if (kurier.isFinalized(j)) break
  }
  save() // on timeout the record keeps its last status; GET /api/job?id= settles it
  return rec
}

/** Sweep (single-flight): refresh every unpaid PAY record from Kurier and release the bounty once the
 *  aggregation is published on Base. Errors are kept on the record and retried next sweep (simulated first). */
let sweeping = false
export async function settlePending(log = console.log) {
  if (sweeping) return
  sweeping = true
  try {
    for (const key of store.list('prs')) {
      let rec = store.read('prs', key)
      if (rec?.decision !== 'PAY' || rec.payout?.txHash) continue
      if (!['aggregated', 'published'].includes(rec.aggregation?.status) || !rec.aggregation?.details) {
        try { rec = store.write('prs', key, apply(rec, await kurier.jobStatus(rec.zkverify.jobId))) } catch (e) { log(`settle ${key}: kurier ${e.message}`); continue }
      }
      if (!releaseArgs(rec)) continue
      try {
        rec.payout.txHash = await release(rec)
        rec.payout.paidAt = new Date().toISOString()
        delete rec.payout.error
        log(`settle ${key}: paid ${rec.payout.amount} to ${rec.facts.payee} in ${rec.payout.txHash}`)
      } catch (e) {
        const msg = String(e.shortMessage || e.message)
        if (/NotVerified/.test(msg)) continue // root not on Base yet: expected, retry next sweep
        rec.payout.error = msg.slice(0, 300); log(`settle ${key}: ${rec.payout.error}`)
      }
      store.write('prs', key, rec)
    }
  } finally { sweeping = false }
}
