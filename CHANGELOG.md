# Changelog — ORDnet MCP Server

All notable changes to the ORDnet MCP server.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [3.3.2] — 2026-08-13 — audit round 4

### Fixed

- **`npm test` now runs the real regression suite** (`test/run.mjs`, bare Node
  with type-stripping — no install step). It previously ran
  `node dist/index.js --test`, which *started the server*, so a green test run
  proved nothing.
- **Policy ceilings are parsed over the full string.** `parseInt` stops at the
  first non-digit, so `ORDNET_POLICY_MAX_SATS_PER_TX=1e9` silently became a
  **1-sat** limit — a value the operator never chose. Such values are now
  refused and fall back to the default instead.
- **Version alignment:** the version strings the server reports (MCP
  initialize response, `/health`) match `package.json` again; they were stuck
  at 3.1.0.

### Tests

- 28, up from 27 — including one that feeds the exact truncation-prone values
  to the ceiling parser.

## [3.3.0] — 2026-08-13 — audit round 2

Second round of the external review. Full detail in
[SECURITY-FIXES-v3.3.0.md](SECURITY-FIXES-v3.3.0.md).

### Security

- **The spend policy was open by default.** `maxSatsPerTx` and
  `maxSatsPerSession` shipped as `null` and `enforcePolicy()` returned early on
  `null` — out of the box there was no limit at all, while the search tools
  spread on-chain (attacker-writable) content unfiltered into the agent's
  context. Prompt injection → unlimited `ordnet_send`. The defaults are now
  real ceilings: 100.000 sats per transaction, 1.000.000 per session. Raising
  them requires the environment variables; opting out requires the literal
  string `unlimited`, which logs a warning. A malformed value falls back to the
  default, not to `null`.

### Tests

- 27, up from 23 — a fresh install with a cleared environment must refuse a
  0.5 BSV send, and nothing may reach the network when the policy blocks.

## [3.2.0] — 2026-08-11 — external security audit

An external review of all ORDnet repositories on 11 August 2026 reported one
critical and two high-severity findings here. Full detail in
[SECURITY-FIXES-audit-2026-08-11.md](SECURITY-FIXES-audit-2026-08-11.md).

This server hands an autonomous agent a funded wallet. The spend policy is the
only thing standing between a confused or manipulated agent and the balance, so
K8 is the one that mattered most.

### Security

- **K8 — the spend policy applied to 3 of 9 broadcast paths.** The other six —
  `inscribe_html`, `inscribe_json`, `inscribe_text` and three domain
  registration tools — called `broadcastTransaction()` directly, so a limit an
  operator set simply did not apply to them. The root cause was structural:
  "enforce, broadcast, record" were three separate calls a tool author had to
  remember in the right order.

  `broadcastGuarded()` is now the **only** way a tool broadcasts. It enforces
  the policy, broadcasts, and records, in that order. A new broadcast tool
  cannot forget the policy without also forgetting to broadcast, because the
  broadcast lives inside the guard.

  Alongside that: the miner fee the builder chose is counted into the spend
  (it was excluded, so the amount checked was not the amount leaving), and the
  agent can no longer reset a session ceiling the operator set.

- **H8 — server-side request forgery.** URLs an agent supplies were fetched
  without restriction, so the server could be pointed at loopback, private
  ranges or the cloud metadata endpoint. `safeFetch()` resolves the host,
  refuses blocked ranges *before* connecting, and pins the connection to the
  vetted IP so a DNS rebind between check and connect cannot slip through.
  Redirects are re-vetted through the same guard. Fixed-host calls to the
  ORDnet API use `withTimeout()`, which adds the timeout without the DNS work.

- **H9 — unbounded inputs.** `opReturnHint` is capped at 1024 bytes and
  `satoshis` has an upper bound, so a malformed or hostile argument cannot
  build an unreasonable transaction.

- `ordnet_generate_wallet` is gated when the server runs over HTTP transport:
  generating a key is a local operation and should not be reachable remotely.

### Fixed

- The README claimed a 2.775-satoshi service fee. The actual fee is **396
  satoshis** across 11 outputs, which the README now shows as a table matching
  the code.
- The tool count was 28; there are **45**.
- The "byte-identical engine" claim is softened to what is actually true.
- `npm test` pointed at a script that did not exist; it now points at
  `test/audit-2026-08-11.test.mjs`.

### Added

- `test/audit-2026-08-11.test.mjs` — 23 regression tests covering the SSRF
  guard and the spend policy, runnable without a live node or wallet.
- `SECURITY.md` with a private disclosure channel and the threat model.

---

## [3.1.0] — 2026-08 — initial public release

First public release: 45 MCP tools for inscriptions, domains, wallet
operations and x402 payments.
