# Security fixes — ORDnet MCP Server v3.3.0

**Audit:** external GitHub review of 13 August 2026
**Supersedes:** v3.2.0

## The spend policy was open by default

```ts
maxSatsPerTx: null
maxSatsPerSession: null
```

and `enforcePolicy()` returns early when both are `null`. **Out of the box there
was no limit at all**: `ordnet_send` accepted up to 2.1 × 10¹⁵ sats and
broadcast immediately. The only brake was `annotations.destructiveHint`, which
is a hint.

That matters more here than in most software, because the second half of the
chain is already present: `ordnet_search_inscriptions` and
`ordnet_get_inscription` spread on-chain content unfiltered into the agent's
context, and on-chain content is writable by anyone for under a cent. Prompt
injection → `ordnet_send` to the attacker's address, unlimited, unconfirmed.

**Now the defaults are real ceilings:** 100.000 sats per transaction and
1.000.000 per session. Generous for ordinary agent work, small enough that a
confused or manipulated agent cannot empty a wallet before a human notices.

Raise them with `ORDNET_POLICY_MAX_SATS_PER_TX` and `_PER_SESSION`, or set
either to the literal string `unlimited` to opt out — spelled out, so it is a
decision rather than an omission, and it logs a warning when used. A malformed
value falls back to the default rather than to `null`.

## Tests

27, up from 23. The new ones import the policy module with a cleared
environment and assert that a fresh install refuses a 0.5 BSV send and that
nothing reaches the network when the policy blocks.

## Still open

`"test": "node dist/index.js --test"` still starts the server rather than
running tests; the real suite needs the `.ts`-specifier rewrite documented at
the top of `test/audit-2026-08-11.test.mjs`. A proper runner is tracked as an
issue.

