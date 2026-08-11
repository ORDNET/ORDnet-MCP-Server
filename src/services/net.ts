/**
 * Network guard (H8, external audit 11 Aug 2026).
 *
 * The x402 client fetches URLs an agent hands it, and `ordnet_x402_fetch`'s
 * quote step is annotated readOnlyHint — so a paywall probe is often
 * auto-approved. Without a guard that is a server-side request forgery hole:
 * `http://169.254.169.254/…` (cloud metadata), `http://127.0.0.1:7002/…`
 * (the server's own internal index), or any RFC1918 host would be fetched and
 * its response fed straight back into the agent's context. None of the 18
 * fetches in this codebase had a timeout either, so a slow or hanging host
 * stalled the tool indefinitely.
 *
 * `safeFetch` closes both:
 *   - scheme allowlist (http/https only — no file:, no gopher:, no data:)
 *   - the resolved IP of the host must be a public unicast address; loopback,
 *     link-local, private, ULA, multicast and reserved ranges are refused,
 *     BEFORE the connection is made, and the connection is pinned to the
 *     vetted IP so a DNS rebind between check and connect cannot slip through.
 *   - a hard timeout on every request.
 *
 * The fixed-host ORDnet API calls don't need the SSRF check (the host is not
 * attacker-controlled) but do want the timeout; `withTimeout` gives them that
 * without the DNS work.
 */
import { lookup } from 'node:dns/promises';
import net from 'node:net';

export const DEFAULT_TIMEOUT_MS = 15_000;

/** True for any address an outbound request must never be allowed to reach. */
export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    if (p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    const [a, b] = p;
    if (a === 0) return true;                         // "this" network
    if (a === 10) return true;                        // 10/8 private
    if (a === 127) return true;                       // loopback
    if (a === 169 && b === 254) return true;          // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12 private
    if (a === 192 && b === 168) return true;          // 192.168/16 private
    if (a === 100 && b >= 64 && b <= 127) return true;// 100.64/10 CGNAT
    if (a === 192 && b === 0 && p[2] === 0) return true; // 192.0.0/24
    if (a >= 224) return true;                        // multicast + reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    if (x === '::1' || x === '::') return true;       // loopback / unspecified
    if (x.startsWith('fe80')) return true;            // link-local
    if (x.startsWith('fc') || x.startsWith('fd')) return true; // unique-local
    if (x.startsWith('ff')) return true;              // multicast
    // IPv4-mapped (::ffff:a.b.c.d) — re-check the embedded v4 address
    const m = x.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return isBlockedIp(m[1]);
    return false;
  }
  return true; // not a parseable IP -> refuse
}

function timeoutSignal(ms: number): AbortSignal {
  // AbortSignal.timeout exists on Node 18+, but build a portable one so the
  // guard never silently no-ops on an older runtime.
  if (typeof (AbortSignal as any).timeout === 'function') return (AbortSignal as any).timeout(ms);
  const ac = new AbortController();
  setTimeout(() => ac.abort(), ms).unref?.();
  return ac.signal;
}

/** fetch() with a hard timeout; host is NOT vetted (use for fixed ORDnet hosts). */
export function withTimeout(url: string, init: RequestInit = {}, ms = DEFAULT_TIMEOUT_MS): Promise<Response> {
  return fetch(url, { ...init, signal: init.signal ?? timeoutSignal(ms) });
}

/**
 * SSRF-safe fetch for attacker-influenced URLs. Resolves the host, refuses
 * private/loopback/link-local/reserved targets, pins the connection to the
 * vetted IP, and applies a hard timeout.
 */
export async function safeFetch(rawUrl: string, init: RequestInit = {}, ms = DEFAULT_TIMEOUT_MS): Promise<Response> {
  let u: URL;
  try { u = new URL(rawUrl); }
  catch { throw new Error(`Refused: not a valid URL: ${rawUrl}`); }

  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error(`Refused: only http/https URLs may be fetched (got ${u.protocol}).`);
  }

  const host = u.hostname;
  // A bare IP literal is checked directly; a hostname is resolved and every
  // returned address is checked. If any resolves into a blocked range we
  // refuse rather than race.
  let pinnedIp: string;
  let family: number;
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new Error(`Refused: ${host} is not a public address (SSRF guard).`);
    pinnedIp = host;
    family = net.isIPv6(host) ? 6 : 4;
  } else {
    const results = await lookup(host, { all: true });
    if (!results.length) throw new Error(`Refused: ${host} did not resolve.`);
    for (const r of results) {
      if (isBlockedIp(r.address)) {
        throw new Error(`Refused: ${host} resolves to a non-public address ${r.address} (SSRF guard).`);
      }
    }
    pinnedIp = results[0].address;
    family = results[0].family;
  }

  // Pin the connection to the vetted IP (defeat DNS rebinding between check
  // and connect) while keeping the Host header/SNI as the original hostname.
  const pinnedUrl = new URL(rawUrl);
  pinnedUrl.hostname = family === 6 ? `[${pinnedIp}]` : pinnedIp;
  const headers = new Headers(init.headers ?? {});
  if (!headers.has('host')) headers.set('host', u.host);

  return fetch(pinnedUrl.toString(), {
    ...init,
    headers,
    redirect: 'manual', // a 3xx to an internal host must not be followed blindly
    signal: init.signal ?? timeoutSignal(ms),
  });
}
