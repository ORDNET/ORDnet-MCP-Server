/**
 * ORDnet MCP Server - Agent Safety Layer (V3 / Pijler 3)
 *
 * Spend policy + transaction simulation, powered by ORDnet's OWN node
 * (api.ordnet.io /v1/bsv/tx/decode -> decoderawtransaction).
 *
 * Design principles:
 * - Default = no behavior change: when no limits are set, broadcasts are
 *   not blocked and no network calls are added.
 * - Fail-closed: when limits ARE set, a broadcast is only allowed after a
 *   successful simulation. If the ORDnet API is unreachable, the broadcast
 *   is blocked (safety over availability).
 * - Limits apply to the TOTAL output value of a transaction (including
 *   change back to the agent's own wallet). This is a conservative upper
 *   bound: without wallet context we cannot reliably separate change from
 *   spend, so we over-count rather than under-count.
 */

import { API_ENDPOINTS } from '../constants.js';
import { withTimeout } from './net.js';

// ============================================================================
// Policy state (in-memory, per server process)
// ============================================================================

export interface SpendPolicy {
  /** Max total output sats allowed per transaction (null = unlimited). */
  maxSatsPerTx: number | null;
  /** Max cumulative output sats across this server session (null = unlimited). */
  maxSatsPerSession: number | null;
  /** Running total of output sats across successful broadcasts this session. */
  spentThisSession: number;
  /** Number of successful broadcasts this session. */
  broadcastCount: number;
}

// ============================================================================
// Server-side hard ceilings (v2.4)
// Set via environment variables by the OPERATOR, not by agents:
//   ORDNET_POLICY_MAX_SATS_PER_TX
//   ORDNET_POLICY_MAX_SATS_PER_SESSION
// ordnet_policy_set can only TIGHTEN below these ceilings, never loosen
// above them. This makes the safety layer meaningful on remote transports
// where the same caller would otherwise simply lift its own limits.
// ============================================================================

function envCeiling(name: string): number | null {
  const raw = process.env[name];
  if (!raw) return null;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export const HARD_CEILINGS = {
  maxSatsPerTx: envCeiling('ORDNET_POLICY_MAX_SATS_PER_TX'),
  maxSatsPerSession: envCeiling('ORDNET_POLICY_MAX_SATS_PER_SESSION')
} as const;

export class PolicyViolationError extends Error {}

const policy: SpendPolicy = {
  maxSatsPerTx: HARD_CEILINGS.maxSatsPerTx,
  maxSatsPerSession: HARD_CEILINGS.maxSatsPerSession,
  spentThisSession: 0,
  broadcastCount: 0
};

/** Clamp a requested limit against an operator ceiling (null = no ceiling). */
function clampToCeiling(requested: number | null, ceiling: number | null): number | null {
  if (ceiling === null) return requested;          // no ceiling -> free choice
  if (requested === null) return ceiling;          // "unlimited" -> ceiling
  return Math.min(requested, ceiling);             // never above ceiling
}

export function setPolicy(opts: {
  maxSatsPerTx?: number | null;
  maxSatsPerSession?: number | null;
  resetSession?: boolean;
}): SpendPolicy {
  if (opts.maxSatsPerTx !== undefined) {
    policy.maxSatsPerTx = clampToCeiling(opts.maxSatsPerTx, HARD_CEILINGS.maxSatsPerTx);
  }
  if (opts.maxSatsPerSession !== undefined) {
    policy.maxSatsPerSession = clampToCeiling(opts.maxSatsPerSession, HARD_CEILINGS.maxSatsPerSession);
  }
  if (opts.resetSession) {
    // K8 (external audit, 11 Aug 2026) — resetSession used to be free: an
    // agent could zero its own session counter and sidestep maxSatsPerSession
    // entirely. When the OPERATOR has set a session ceiling via env, the
    // agent may no longer reset the counter through this tool; only a fresh
    // server process (a new operator-controlled session) resets it. With no
    // operator ceiling there is nothing to protect, so a reset is still
    // allowed for convenience.
    if (HARD_CEILINGS.maxSatsPerSession !== null) {
      throw new PolicyViolationError(
        'resetSession is refused: the operator has set a session ceiling ' +
        '(ORDNET_POLICY_MAX_SATS_PER_SESSION), and the session counter cannot ' +
        'be reset from within the session. Restart the server to begin a new session.'
      );
    }
    policy.spentThisSession = 0;
    policy.broadcastCount = 0;
  }
  return { ...policy };
}

export function getPolicy(): SpendPolicy {
  return { ...policy };
}

// ============================================================================
// Transaction simulation (dry-run) via ORDnet's own node
// ============================================================================

export interface SimulatedOutput {
  vout: number;
  satoshis: number;
  address: string | null;
  scriptType: string;
}

export interface TxSimulation {
  txid: string | null;
  sizeBytes: number;
  outputCount: number;
  totalOutputSats: number;
  /** Outputs excluding change back to the wallet's own address — what actually leaves the wallet. */
  spendSats: number;
  /** Miner fee counted into spendSats (K8), when the builder supplied it. */
  minerFee: number;
  outputs: SimulatedOutput[];
  warnings: string[];
}

interface DecodedVout {
  value?: number;
  n?: number;
  scriptPubKey?: {
    type?: string;
    addresses?: string[];
    asm?: string;
  };
}

interface DecodedTx {
  txid?: string;
  size?: number;
  vout?: DecodedVout[];
  error?: unknown;
}

/**
 * Decode a raw transaction via ORDnet's own node WITHOUT broadcasting it.
 * Returns a human/agent-readable summary with safety warnings.
 */
export async function simulateTransaction(txHex: string): Promise<TxSimulation> {
  const response = await withTimeout(`${API_ENDPOINTS.ORDNET_API}/v1/bsv/tx/decode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rawtx: txHex })
  });

  if (!response.ok) {
    throw new Error(`Simulation failed: ORDnet API returned HTTP ${response.status}`);
  }

  const decoded = await response.json() as DecodedTx;
  if (!decoded || decoded.error || !Array.isArray(decoded.vout)) {
    const detail = decoded && decoded.error ? JSON.stringify(decoded.error) : 'unexpected response';
    throw new Error(`Simulation failed: transaction could not be decoded (${detail})`);
  }

  const outputs: SimulatedOutput[] = [];
  const warnings: string[] = [];
  let totalOutputSats = 0;

  for (const v of decoded.vout) {
    const sats = Math.round((v.value ?? 0) * 1e8);
    totalOutputSats += sats;
    const scriptType = v.scriptPubKey?.type ?? 'unknown';
    outputs.push({
      vout: v.n ?? outputs.length,
      satoshis: sats,
      address: v.scriptPubKey?.addresses?.[0] ?? null,
      scriptType
    });

    if (sats === 1) {
      warnings.push(
        `Output ${v.n ?? outputs.length - 1} is a 1-satoshi output: this is very likely an ordinal/inscription. ` +
        `Verify this is intentional before broadcasting.`
      );
    }
  }

  if (totalOutputSats === 0) {
    warnings.push('Transaction has zero total output value (data-only transaction).');
  }

  return {
    txid: decoded.txid ?? null,
    sizeBytes: decoded.size ?? Math.floor(txHex.length / 2),
    outputCount: outputs.length,
    totalOutputSats,
    spendSats: totalOutputSats, // recomputed in enforcePolicy when ownAddress is known
    minerFee: 0,
    outputs,
    warnings
  };
}

// ============================================================================
// Policy enforcement (called before every broadcast)
// ============================================================================

/**
 * Enforce the active spend policy against a raw transaction.
 *
 * - No limits configured -> returns null immediately (zero added latency,
 *   zero new failure modes; identical to pre-V3 behavior).
 * - Limits configured -> simulates via ORDnet's own node and throws
 *   PolicyViolationError when a limit would be exceeded. Fail-closed.
 */
export async function enforcePolicy(txHex: string, ownAddress?: string, knownMinerFee?: number): Promise<TxSimulation | null> {
  if (policy.maxSatsPerTx === null && policy.maxSatsPerSession === null) {
    return null;
  }

  const sim = await simulateTransaction(txHex);

  // v3.0.1: change back to the wallet's own address is not spending.
  // The policy limits what LEAVES the wallet, so exclude own-address outputs.
  const changeSats = ownAddress
    ? sim.outputs
        .filter(o => o.address === ownAddress)
        .reduce((acc, o) => acc + o.satoshis, 0)
    : 0;

  // K8 (external audit, 11 Aug 2026) — count the miner fee.
  // The decode only exposes OUTPUTS, so a policy that looked at outputs alone
  // was blind to the miner fee: a hostile x402 counterparty could answer with
  // a 1,000-sat price and a 10 MB opReturnHint, driving a ~1.5M-sat miner fee
  // that enforcePolicy never saw. The builder always knows the fee it chose,
  // so it is passed in here and added to what leaves the wallet. When it is
  // not supplied, we fall back to deriving it from the decode where possible
  // (own-node decodes may include a `fee`), and otherwise over-count by not
  // subtracting change — safety over precision.
  const minerFee = Number.isFinite(knownMinerFee as number) && (knownMinerFee as number) >= 0
    ? Math.round(knownMinerFee as number)
    : 0;
  sim.minerFee = minerFee;
  sim.spendSats = (sim.totalOutputSats - changeSats) + minerFee;

  if (policy.maxSatsPerTx !== null && sim.spendSats > policy.maxSatsPerTx) {
    throw new PolicyViolationError(
      `Blocked by spend policy: transaction spends ${sim.spendSats} sats ` +
      `(outputs ${sim.totalOutputSats} minus ${changeSats} change to own address, ` +
      `plus ${minerFee} miner fee), ` +
      `which exceeds maxSatsPerTx (${policy.maxSatsPerTx}). ` +
      `Adjust the policy with ordnet_policy_set if this is intentional.`
    );
  }

  if (
    policy.maxSatsPerSession !== null &&
    policy.spentThisSession + sim.spendSats > policy.maxSatsPerSession
  ) {
    throw new PolicyViolationError(
      `Blocked by spend policy: this transaction (${sim.spendSats} sats spend) plus ` +
      `already-spent session total (${policy.spentThisSession} sats) exceeds ` +
      `maxSatsPerSession (${policy.maxSatsPerSession}). ` +
      `Adjust or reset the policy with ordnet_policy_set if this is intentional.`
    );
  }

  return sim;
}

/** Record a successful broadcast against the session totals. */
export function recordBroadcast(sim: TxSimulation | null): void {
  if (sim) {
    policy.spentThisSession += sim.spendSats;
  }
  policy.broadcastCount += 1;
}

// ============================================================================
// K8 — the single guarded broadcast path
// ============================================================================
//
// The audit found the spend policy wired into only 3 of 9 broadcast paths:
// the other 6 (inscribe_html/json/text, domain_register x3) called
// broadcastTransaction() directly, so the limit an operator set simply did
// not apply to them. The root cause is that "enforce, broadcast, record" was
// three separate calls a tool author had to remember in the right order.
//
// broadcastGuarded() makes that impossible to get wrong: it is the ONLY way a
// tool broadcasts. It enforces the policy (counting the miner fee the builder
// chose), broadcasts, and records — atomically, in order. A new broadcast
// tool that forgets the policy cannot be written without also forgetting to
// broadcast, because the broadcast lives inside the guard.
export async function broadcastGuarded(
  broadcastFn: (rawHex: string) => Promise<string>,
  rawHex: string,
  ownAddress?: string,
  knownMinerFee?: number
): Promise<{ txid: string; simulation: TxSimulation | null }> {
  const simulation = await enforcePolicy(rawHex, ownAddress, knownMinerFee);
  const txid = await broadcastFn(rawHex);
  recordBroadcast(simulation);
  return { txid, simulation };
}
