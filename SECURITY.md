# Security Policy

## Reporting a vulnerability

Please report security issues privately first. Do not open a public issue for
anything that could move funds or expose a key.

**Preferred channel:** [GitHub private vulnerability reporting](https://github.com/ORDNET/ORDnet-MCP-Server/security/advisories/new)
— the "Report a vulnerability" button on the Security tab of this repository.
This creates a private advisory only the maintainers can see.

Please include what the issue is, which file and line, how to reproduce it,
and what an attacker gains.

## What to expect

- **Acknowledgement:** within 3 working days.
- **Assessment:** within 10 working days, with a severity.
- **Fix:** anything that can move funds, spend beyond the policy, exfiltrate a
  key, or reach an internal service is prioritised over everything else.
- **Credit:** we will name you in the release notes unless you prefer otherwise.

We do not currently operate a bug bounty.

## Threat model

This server lets an autonomous agent hold a hot BSV key and broadcast
transactions. The assumptions that matter:

1. **The agent's prompt is attacker-influenceable.** Anything a tool builds
   from tool arguments, x402 quotes, or fetched content may be adversarial.
   The spend policy is the backstop and every broadcast goes through the one
   guarded path (`broadcastGuarded`) that enforces it — including the miner
   fee, not just the outputs.

2. **URLs handed to the server are hostile.** The x402 client fetches through
   an SSRF guard (`src/services/net.ts`) that refuses loopback, link-local
   (incl. the cloud metadata address), private, ULA and multicast targets,
   pins the connection to the vetted IP, re-vets every redirect, and times
   out. Do not add a raw `fetch()` on an agent-supplied URL — use `safeFetch`.

3. **Plaintext keys never cross the network.** WIF-returning and WIF-accepting
   tools are disabled on the HTTP transport (`IS_HTTP_TRANSPORT`). On HTTP,
   provide the key out-of-band via `ORDNET_WIF` + `ordnet_wallet_init_env`.

## Operator responsibilities

- Set `ORDNET_MCP_AUTH_TOKEN` (the HTTP transport refuses to start without it).
- Set `ORDNET_POLICY_MAX_SATS_PER_TX` and `ORDNET_POLICY_MAX_SATS_PER_SESSION`
  as hard ceilings. With a session ceiling set, the agent cannot reset the
  session counter — only restarting the server (an operator action) does.
- Point `ORDNET_API` / `ORDNET_UTXO_URL` at nodes you trust.

## Running the audit regression tests

```
node --experimental-strip-types test/audit-2026-08-11.test.mjs
```

(If your Node build resolves NodeNext `.js` specifiers only after a build,
run `npm run build` first, or run the test against a source tree whose
relative specifiers end in `.ts`.)
