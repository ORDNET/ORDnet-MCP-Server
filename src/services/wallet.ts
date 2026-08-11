/**
 * ORDnet MCP Server - BSV Wallet Service
 * 
 * Handles wallet operations using bsv v1.5.6
 * Byte-identical transaction structure to ORD-inscriber-pro-009.html
 */

// @ts-ignore - bsv v1.x has no TypeScript definitions
import bsv from 'bsv';
import { withTimeout } from './net.js';
import { API_ENDPOINTS, UTXO_INDEX_BASE, TX_CONSTANTS } from '../constants.js';
import type { 
  UTXO, 
  WalletBalance, 
  WalletInfo, 
  WOCBalanceResponse, 
  WOCUnspentResponse 
} from '../types.js';

// ============================================================================
// Wallet Management
// ============================================================================

let currentPrivateKey: typeof bsv.PrivateKey | null = null;

/**
 * Initialize wallet from WIF private key
 */
export function initializeWallet(wif: string): WalletInfo {
  try {
    const privateKey = bsv.PrivateKey.fromWIF(wif);
    const address = privateKey.toAddress().toString();
    const publicKey = privateKey.toPublicKey().toString();
    
    currentPrivateKey = privateKey;
    
    return {
      address,
      publicKey,
      balanceSatoshis: 0,
      balanceBSV: '0.00000000',
      utxoCount: 0
    };
  } catch (error) {
    throw new Error(`Invalid WIF private key: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Get current wallet address
 */
export function getWalletAddress(): string | null {
  if (!currentPrivateKey) return null;
  return currentPrivateKey.toAddress().toString();
}

/**
 * Check if wallet is initialized
 */
export function isWalletInitialized(): boolean {
  return currentPrivateKey !== null;
}

/**
 * Get current private key (for internal use only)
 */
export function getPrivateKey(): typeof bsv.PrivateKey {
  if (!currentPrivateKey) {
    throw new Error('Wallet not initialized. Call ordnet_wallet_init first.');
  }
  return currentPrivateKey;
}

/**
 * Clear wallet from memory
 */
export function clearWallet(): void {
  currentPrivateKey = null;
}

// ============================================================================
// Balance & UTXOs — v2.5: primary source is ORDnet's OWN address index
// (ordnet-utxo on port 7002, node-verified watchlist). WhatsOnChain is a
// connectivity fallback ONLY: a 4xx from the index (e.g. invalid address)
// is authoritative, exactly like the broadcast pattern. A 5xx or network
// failure falls back to WOC so wallet ops keep working if the index is down.
// ============================================================================

interface IndexBalanceResponse {
  address: string;
  balance: number;
  utxo_count: number;
  confirmed: number;
  unconfirmed: number;
}

interface IndexUtxosResponse {
  address: string;
  utxos: Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>;
}

class IndexAuthoritativeError extends Error {}

async function indexGet(path: string): Promise<any> {
  const response = await withTimeout(`${UTXO_INDEX_BASE}${path}`);
  if (response.ok) return response.json();
  const body = await response.text().catch(() => '');
  if (response.status >= 400 && response.status < 500) {
    // Honest, authoritative rejection by our own index — do NOT fall back
    throw new IndexAuthoritativeError(`ordnet-utxo ${response.status}: ${body}`);
  }
  throw new Error(`ordnet-utxo unavailable (HTTP ${response.status}): ${body}`);
}

/**
 * Fetch wallet balance. Primary: own index (7002). Fallback: WhatsOnChain.
 */
export async function fetchBalance(address: string): Promise<WalletBalance> {
  try {
    const d = await indexGet(`/v1/bsv/address/${address}/balance`) as IndexBalanceResponse;
    return {
      confirmed: d.confirmed,
      unconfirmed: d.unconfirmed,
      total: d.balance
    };
  } catch (error) {
    if (error instanceof IndexAuthoritativeError) throw error;
    console.error(`[wallet] own index failed, falling back to WOC: ${error instanceof Error ? error.message : error}`);
  }

  const response = await withTimeout(`${API_ENDPOINTS.WOC_BASE}/address/${address}/balance`);
  if (!response.ok) {
    throw new Error(`Failed to fetch balance (index down, WOC HTTP ${response.status})`);
  }
  const data = await response.json() as WOCBalanceResponse;
  return {
    confirmed: data.confirmed,
    unconfirmed: data.unconfirmed,
    total: data.confirmed + data.unconfirmed
  };
}

/**
 * Fetch UTXOs. Primary: own index (7002). Fallback: WhatsOnChain.
 * Maps to the same format as ORD-inscriber-pro-009.html.
 */
export async function fetchUTXOs(address: string, limit: number = 50): Promise<UTXO[]> {
  let raw: Array<{ tx_hash: string; tx_pos: number; value: number }>;

  try {
    const d = await indexGet(`/v1/bsv/address/${address}/utxos`) as IndexUtxosResponse;
    raw = d.utxos;
  } catch (error) {
    if (error instanceof IndexAuthoritativeError) throw error;
    console.error(`[wallet] own index failed, falling back to WOC: ${error instanceof Error ? error.message : error}`);
    const response = await withTimeout(`${API_ENDPOINTS.WOC_BASE}/address/${address}/unspent`);
    if (!response.ok) {
      throw new Error(`Failed to fetch UTXOs (index down, WOC HTTP ${response.status})`);
    }
    raw = await response.json() as WOCUnspentResponse[];
  }

  const sorted = raw.sort((a, b) => b.value - a.value); // largest first, so the limit never hides the funding UTXO
  const mappedUtxos: UTXO[] = [];

  for (const utxo of sorted.slice(0, limit)) {
    try {
      const addressObj = bsv.Address.fromString(address);
      const script = bsv.Script.buildPublicKeyHashOut(addressObj);

      mappedUtxos.push({
        txid: utxo.tx_hash,
        vout: utxo.tx_pos,
        satoshis: utxo.value,
        script: script.toHex(),
        scriptPubKey: script.toHex()
      });
    } catch (error) {
      console.error('Error processing UTXO:', error);
      continue;
    }
  }

  return mappedUtxos;
}

/**
 * v2.5: index health + watchlist registration (used by the new MCP tools).
 */
export async function fetchIndexHealth(): Promise<{ status: string; index_height: number; node_height: number }> {
  const response = await withTimeout(`${UTXO_INDEX_BASE}/health`);
  if (!response.ok) throw new Error(`ordnet-utxo health failed: HTTP ${response.status}`);
  return response.json() as Promise<{ status: string; index_height: number; node_height: number }>;
}

export async function watchAddress(address: string, label?: string): Promise<any> {
  const response = await withTimeout(`${UTXO_INDEX_BASE}/v1/watch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address, label: label || 'mcp' })
  });
  const body = await response.text();
  if (!response.ok) throw new Error(`watch failed (HTTP ${response.status}): ${body}`);
  try { return JSON.parse(body); } catch { return { raw: body }; }
}

/**
 * Broadcast transaction to BSV network.
 * Primary: ORDnet's own node via api.ordnet.io (/v1/bsv/tx/broadcast).
 * Fallback: WhatsOnChain — ONLY on connectivity/server errors, never when
 * the own node rejected the transaction (a rejection is authoritative).
 */
export async function broadcastTransaction(txHex: string): Promise<string> {
  // --- Primary: own ORDnet node ---
  try {
    const response = await withTimeout(`${API_ENDPOINTS.ORDNET_API}/v1/bsv/tx/broadcast`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ rawtx: txHex })
    });

    if (response.ok) {
      const result = await response.json() as { txid?: string };
      if (result.txid) {
        return result.txid;
      }
      throw new Error('ORDnet broadcast: unexpected response shape');
    }

    if (response.status === 400) {
      // Node rejected the transaction — authoritative, do NOT fall back
      const err = await response.json().catch(() => ({})) as { error?: string; detail?: string };
      throw new Error(`Broadcast rejected by ORDnet node: ${err.error ?? 'rejected'}${err.detail ? ` — ${err.detail}` : ''}`);
    }

    // 5xx or other unexpected status → treat as connectivity issue, try fallback
    throw new ConnectivityError(`ORDnet API returned HTTP ${response.status}`);
  } catch (error) {
    if (!(error instanceof ConnectivityError) && !(error instanceof TypeError)) {
      // Real rejection or shape error — propagate, no fallback
      throw error;
    }
    // TypeError = fetch network failure; ConnectivityError = 5xx → fallback below
  }

  // --- Fallback: WhatsOnChain (connectivity issues only) ---
  const response = await withTimeout(`${API_ENDPOINTS.WOC_BASE}/tx/raw`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ txhex: txHex })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Broadcast failed (ORDnet unreachable, WOC fallback): ${errorText}`);
  }

  const result = await response.text();
  // Remove quotes from response
  return result.replace(/"/g, '');
}

/** Marker error: own-API connectivity problem (5xx) that permits WOC fallback. */
class ConnectivityError extends Error {}

// ============================================================================
// Address Validation
// ============================================================================

/**
 * Validate BSV address
 */
export function validateAddress(address: string): boolean {
  try {
    bsv.Address.fromString(address);
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate new random wallet (for testing)
 */
export function generateWallet(): { wif: string; address: string } {
  const privateKey = new bsv.PrivateKey();
  return {
    wif: privateKey.toWIF(),
    address: privateKey.toAddress().toString()
  };
}
