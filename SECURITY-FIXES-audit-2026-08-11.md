# Security fixes — external audit of 11 August 2026 (MCP server)

**Released in:** v3.2.0
**Audit date:** 11 August 2026

Findings K8, H8 and H9 from the 11 Aug 2026 external audit, plus the README
corrections from chapter 5.4. Regression tests: `test/audit-2026-08-11.test.mjs`
(23 passing).

## K8 — there was effectively no spend limit

The audit found four separate gaps that together meant the policy did not
constrain spending:

- **Only 3 of 9 broadcast paths enforced it.** `inscribe_html/json/text` and
  the three `domain_register*` tools called `broadcastTransaction()` directly,
  so any operator limit simply did not apply to them.
- **`resetSession: true` was ungated.** An agent could zero its own session
  counter and sidestep `maxSatsPerSession` entirely.
- **The miner fee was not counted.** The policy looked at output satoshis only.
  A hostile x402 counterparty could answer with a 1,000-sat price and a 10 MB
  `opReturnHint`, driving a ~1.5M-sat miner fee the policy never saw.
- **`SendSchema.satoshis` had no `.max()`.**

**Fix.**

- A single guarded path: `broadcastGuarded(broadcastFn, rawHex, ownAddress,
  knownMinerFee)` in `src/services/policy.ts` is now the *only* way a tool
  broadcasts. It enforces the policy, broadcasts, and records the session
  total — atomically, in order. A new broadcast tool cannot forget the policy
  without also forgetting to broadcast, because the broadcast lives inside the
  guard. All 10 broadcast paths were converted to it.
- `enforcePolicy` now adds the builder's chosen miner fee to what leaves the
  wallet. Every build path passes it; the x402 payment path also caps
  `opReturnHint` at 1024 bytes before building.
- `setPolicy({ resetSession: true })` is refused when the operator has set
  `ORDNET_POLICY_MAX_SATS_PER_SESSION`. Only restarting the server resets the
  counter.
- `SendSchema.satoshis` is capped at the whole BSV supply (2.1e15 sats).

## H8 — SSRF via the x402 client

`x402Quote` (annotated `readOnlyHint`, so often auto-approved) and
`x402RetryWithProof` fetched agent-supplied URLs with no guard and no timeout.
`http://169.254.169.254/…` (cloud metadata) or `http://127.0.0.1:7002/…` (the
server's own internal index) would be fetched and the response fed back into
the agent's context. None of the 18 fetches in the codebase had a timeout.

**Fix.** `src/services/net.ts`:

- `safeFetch(url)` — http/https only; resolves the host and refuses loopback,
  link-local (incl. metadata), RFC1918, CGNAT, ULA, multicast and reserved
  ranges (v4, v6 and IPv4-mapped); pins the connection to the vetted IP so a
  DNS rebind between check and connect cannot slip through; manual redirects,
  re-vetted per hop; hard timeout. The x402 client uses it exclusively.
- `withTimeout(url)` — a timeout wrapper applied to every fixed-host ORDnet /
  WhatsOnChain fetch.
- `ORDNET_API` is now overridable via env, so an operator can point simulation
  and broadcast at their own node.

## H9 — a fresh WIF was returned over HTTP

`ordnet_generate_wallet` returned a freshly generated private key in the tool
output with no transport guard — a plaintext key over the network on the HTTP
transport. The `IS_HTTP_TRANSPORT` guard was present on `ordnet_wallet_init`
and `ordnet_security_encrypt_wallet` but missing here.

**Fix.** The guard was added: on the HTTP transport the tool refuses and
directs the operator to generate the key offline and supply it via
`ORDNET_WIF` + `ordnet_wallet_init_env`.

## Chapter 5.4 — README corrections

- The fictional **"2,775 satoshis"** fee table (six outputs, addresses that
  appear in no file) was replaced with the real **396-sat / 11-output** table
  generated from `SERVICE_FEE_OUTPUTS` in `src/constants.ts`, which is now
  named as the single source of truth.
- The transaction-structure block was corrected to the real 11-fee-output
  layout.
- The **"byte-identical"** claim was reduced to the accurate "follows the same
  output layout as the reference inscriber."
- The **tool count** was reconciled: the header comment (28) and the category
  breakdown (which summed to 28) are now 45, matching the 45 registered tools
  and `totalTools`. All 17 previously-undocumented tools (payments, identity,
  utilities) are now listed.
- The test command pointed at a non-existent `test/transaction-test.mjs`; it
  now points at the real `test/audit-2026-08-11.test.mjs`.
