/**
 * x402 client (v3.1) — the BUYER side of the x402 protocol.
 *
 * Lets an agent consume any x402-paywalled resource in one tool call:
 * request → detect 402 → parse PaymentRequirements → pay in native BSV sats
 * (own wallet, spend policy enforced) → retry with X-PAYMENT → return the
 * resource plus the settlement receipt.
 *
 * Scope: the "exact" scheme on network "bsv" (ORDnet-style facilitators).
 * Offers priced in other networks/assets (e.g. USDC on Base) are reported
 * honestly as unsupported instead of guessed at.
 */

import { safeFetch } from './net.js';

/**
 * safeFetch with manual redirects re-vetted through the same SSRF guard.
 * A server can 402/200 directly, or 3xx to another public URL; each hop is
 * checked, and more than 5 hops is refused.
 */
async function followSafely(url: string, init: RequestInit, maxHops = 5): Promise<Response> {
  let current = url;
  for (let hop = 0; hop <= maxHops; hop++) {
    const res = await safeFetch(current, init);
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) return res;
      current = new URL(loc, current).toString(); // safeFetch re-vets on next loop
      continue;
    }
    return res;
  }
  throw new Error('Refused: too many redirects.');
}

export interface X402Requirements {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  resource: string;
  description?: string;
  mimeType?: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  asset?: string;
  extra?: { invoiceId?: string; opReturnHint?: string };
}

export interface X402Quote {
  status: number;
  isPaywalled: boolean;
  accepts: X402Requirements[];
  bsvOffer: X402Requirements | null;
  body: unknown;
}

/** Request a URL without paying; parse the 402 quote when present. */
export async function x402Quote(url: string, method: string = 'GET'): Promise<X402Quote> {
  // H8: the URL is agent-supplied and this path is often auto-approved
  // (readOnlyHint). safeFetch refuses private/loopback/metadata targets and
  // applies a timeout. Redirects are manual so a 3xx to an internal host is
  // followed only after the same guard re-vets the new location.
  const response = await followSafely(url, { method });
  const text = await response.text();
  let body: unknown = text;
  try { body = JSON.parse(text); } catch { /* non-JSON body is fine */ }

  if (response.status !== 402) {
    return { status: response.status, isPaywalled: false, accepts: [], bsvOffer: null, body };
  }

  // Prefer the PAYMENT-REQUIRED header (Base64 JSON per x402 V2), fall back to the body
  let parsed: any = body;
  const header = response.headers.get('PAYMENT-REQUIRED');
  if (header) {
    try { parsed = JSON.parse(Buffer.from(header, 'base64').toString('utf8')); } catch { /* keep body */ }
  }

  const accepts: X402Requirements[] = Array.isArray(parsed?.accepts) ? parsed.accepts : [];
  const bsvOffer = accepts.find(a => a.network === 'bsv' && a.scheme === 'exact') ?? null;
  return { status: 402, isPaywalled: true, accepts, bsvOffer, body: parsed };
}

export interface X402FetchResult {
  status: number;
  body: unknown;
  receipt: unknown | null;
  paid: { txid: string; satoshis: number; payTo: string } | null;
}

/**
 * Retry the request with an X-PAYMENT proof after the caller has broadcast
 * the payment. Kept separate from payment construction so the tool layer can
 * run the payment through the existing wallet + policy machinery.
 */
export async function x402RetryWithProof(
  url: string,
  method: string,
  txid: string,
  invoiceId: string | undefined
): Promise<X402FetchResult> {
  const payload = {
    x402Version: 2,
    scheme: 'exact',
    network: 'bsv',
    payload: { txid, ...(invoiceId ? { invoiceId } : {}) }
  };
  const response = await followSafely(url, {
    method,
    headers: { 'X-PAYMENT': Buffer.from(JSON.stringify(payload)).toString('base64') }
  });
  const text = await response.text();
  let body: unknown = text;
  try { body = JSON.parse(text); } catch { /* non-JSON body is fine */ }

  let receipt: unknown | null = null;
  const receiptHeader = response.headers.get('X-PAYMENT-RESPONSE');
  if (receiptHeader) {
    try { receipt = JSON.parse(Buffer.from(receiptHeader, 'base64').toString('utf8')); } catch { /* ignore */ }
  }
  return { status: response.status, body, receipt, paid: null };
}
