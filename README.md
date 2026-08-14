# ORDnet MCP Server v3.3

> Enable AI agents to create Web3 content on Bitcoin SV blockchain

[![Version](https://img.shields.io/badge/version-3.3.2-blue.svg)](https://github.com/ORDNET/ORDnet-MCP-Server)
[![tests](https://github.com/ORDNET/ORDnet-MCP-Server/actions/workflows/test.yml/badge.svg)](https://github.com/ORDNET/ORDnet-MCP-Server/actions/workflows/test.yml)
[![test count](https://img.shields.io/badge/tests-28_passing-2b8a3e?style=flat-square)](#development)
[![tools](https://img.shields.io/badge/MCP_tools-45-364fc7?style=flat-square)](#tools-reference)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

ORDnet MCP Server enables AI agents (Claude, GPT, etc.) to create permanent, censorship-resistant content on the Bitcoin SV blockchain using the 1SatOrdinals protocol. This is a key component of the **freedom of speech** infrastructure - allowing AI to autonomously publish Web3 content.

### Key Features

- **45 MCP Tools** for complete blockchain content creation, payments and transfers
- **BRC-100 aligned identity** (v3.0): `ordnet_identity`, `ordnet_sign_message`, `ordnet_verify_message`, `ordnet_derive_payment_address` — agent identity, off-chain signing, and per-invoice payment-address derivation as the foundation for x402
- **Agent payments**: `ordnet_send` (P2PKH + optional OP_RETURN reference, miner fee only — x402-ready), `ordnet_transfer` for ordinals/domains (1SatOrdinals input-0/output-0 semantics, outpoint verified via own node)
- **Binary inscriptions** via `ordnet_inscribe_binary` (base64 → bytes untouched); BSVmap tile claims via `ordnet_bsvmap_inscribe`
- **Agent conveniences**: `ordnet_tx_status` (confirmations via own node), `ordnet_price` (via own CoinGecko proxy)
- **3 MCP Prompts** (`prompts/list`): inscribe-website, register-domain, agent-payment
- **1SatOrdinals inscriptions** (HTML, JSON, text, images, etc.)
- **SNS/OPNS domain registration** (.sats, .btc, .bsv, etc.)
- **3-tier wallet security** (env vars → encrypted → plaintext; plaintext-WIF tools are disabled on the HTTP transport)
- **Agent safety layer**: tx simulation via ORDnet's own node + spend limits with operator-set hard ceilings (fail-closed)
- **HTTP transport with mandatory bearer auth** (`ORDNET_MCP_AUTH_TOKEN`, server refuses to start without it)
- **Agent-tier service fee**: **396 satoshis** across 11 outputs to 10 addresses, plus a miner fee of 0.15 sat/byte (min. 200 sats). That is deliberately **one tenth** of the 3.996-satoshi fee the ORDnet wallets charge — an agent inscribes far more often than a person does, so the per-transaction fee is scaled down to match. The same agent tier applies to ORDmail. See [Service fees](#service-fees) for the exact split.

## Quick Start

### Installation

```bash
git clone https://github.com/ORDNET/ORDnet-MCP-Server.git && cd ORDnet-MCP-Server
npm install && npm run build
```

> Note: the package is not (yet) published on npm; install from source.

### Usage with Claude Desktop

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ordnet": {
      "command": "node",
      "args": ["/absolute/path/to/ORDnet-MCP-Server/dist/index.js"],
      "env": {
        "ORDNET_WIF": "your-wif-private-key"
      }
    }
  }
}
```

### Usage with OpenClaw

```json
{
  "mcp_servers": [
    {
      "name": "ordnet",
      "command": "node",
      "args": ["/path/to/ordnet-mcp-server/dist/index.js"],
      "env": {
        "ORDNET_WIF": "your-wif-private-key"
      }
    }
  ]
}
```

## Service Fees

Every inscription includes a total service fee of **396 satoshis**, split
across **11 outputs** to 10 addresses (monitor and founder share one),
exactly as defined in `src/constants.ts` (`SERVICE_FEE_OUTPUTS`). These are
the values the code actually writes:

| Label | Amount | Address |
|-------|--------|---------|
| ordiBuilder | 11 sats | `1HdbyucjYU2yfDFXzAQt3kCdP3VvM4tjzr` |
| onnoBuilder | 11 sats | `1JKcD1kx8XeJFfd32sug1MaXfruurHTCjv` |
| algoBuilder | 11 sats | `1AHEUcWuCfdRnfwNsvwZhZSetXjEuAvBot` |
| colleagueI | 11 sats | `1ENW3XBoAv4KQ4FuQ4MtzNkLq82eJd12PV` |
| protocol | 22 sats | `15q8YQSqUa9uTh6gh4AVixxq29xkpBBP9z` |
| colleagueD | 22 sats | `1GeifRjPLWTDqL1DZ2vaqorX6pqCi9PyJB` |
| monitor | 33 sats | `1EXupec98g8TDTG5cwJwH3U8V3PezvvLv8` |
| indexer | 44 sats | `18RHRqQhsKKZwMnGevvnRQ8KrryAXvQUWQ` |
| partner | 66 sats | `19o4rByWRvdq6zziJEfhpe4xdq5z43jYrr` |
| founder | 77 sats | `1EXupec98g8TDTG5cwJwH3U8V3PezvvLv8` |
| foundation | 88 sats | `1ATEXPH6FSctbZdAz8MnXCfDpCvDnFrWma` |
| **Total** | **396 sats** | 11 outputs |

Miner fee is separate: `0.15 sat/byte`, minimum 200 sats.

### Why 396 and not 3.996

The ORDnet wallets (Chrome extension, iOS, Android) charge **3.996 satoshis**
over the same 11-output structure — every amount is exactly ten times the one
above. That is not a discrepancy between products: agents and mail run on a
deliberately reduced **agent tier**, because an autonomous agent inscribes far
more often than a person opening a wallet. The split across recipients is
identical; only the scale differs.

| Tier | Products | Total per inscription |
|---|---|---|
| Wallet | Chrome extension, iOS, Android | 3.996 sats |
| Agent | this MCP server, ORDmail | 396 sats |

> Note: `ordnet_send` (plain payments / x402 micropayments) carries **no**
> service fee — only the miner fee — so agent-to-agent payments stay lean.
> The x402 facilitator has no service-fee outputs at all.

## Tools Reference

### Wallet Management (6 tools)

| Tool | Description |
|------|-------------|
| `ordnet_wallet_init` | Initialize wallet from WIF private key † |
| `ordnet_wallet_init_env` | Initialize from environment variable (recommended) |
| `ordnet_wallet_status` | Check wallet status and balance |
| `ordnet_wallet_balance` | Get balance for any BSV address |
| `ordnet_wallet_utxos` | Get unspent transaction outputs |
| `ordnet_wallet_clear` | Clear wallet from memory |

### Inscriptions (6 tools)

| Tool | Description |
|------|-------------|
| `ordnet_fee_estimate` | Calculate fee for an inscription |
| `ordnet_inscribe_prepare` | Prepare inscription (no broadcast) |
| `ordnet_inscribe_broadcast` | Broadcast prepared transaction |
| `ordnet_inscribe_html` | Quick HTML inscription |
| `ordnet_inscribe_json` | Quick JSON inscription |
| `ordnet_inscribe_text` | Quick plain text inscription |

### Domains (6 tools)

| Tool | Description |
|------|-------------|
| `ordnet_domain_check` | Check domain availability |
| `ordnet_domain_info` | Get domain information |
| `ordnet_domain_search` | Search registered domains |
| `ordnet_domain_register` | Register SNS/OPNS domain |
| `ordnet_domain_register_sns` | Quick SNS registration |
| `ordnet_domain_register_opns` | Quick OPNS registration |

### Search & Lookup (4 tools)

| Tool | Description |
|------|-------------|
| `ordnet_search_inscriptions` | Search inscriptions |
| `ordnet_get_inscription` | Get inscription details |
| `ordnet_get_content_url` | Get content URLs |
| `ordnet_validate_address` | Validate BSV address |

### Security (4 tools)

| Tool | Description |
|------|-------------|
| `ordnet_security_encrypt_wallet` | Encrypt WIF with AES-256-GCM |
| `ordnet_security_tier` | Check security tier |
| `ordnet_security_validate_password` | Validate password strength |
| `ordnet_generate_wallet` | Generate new random wallet † |

### Payments (5 tools)

| Tool | Description |
|------|-------------|
| `ordnet_send` | Plain BSV payment (miner fee only, no service fee) |
| `ordnet_transfer` | Transfer an ordinal/domain to another address |
| `ordnet_x402_quote` | Probe an x402-paywalled URL and parse the quote (SSRF-guarded) |
| `ordnet_x402_fetch` | Pay an x402 resource in native sats and retrieve it |
| `ordnet_derive_payment_address` | Derive a BRC-42 payment address (watch-only) |

### Identity & signing (3 tools)

| Tool | Description |
|------|-------------|
| `ordnet_identity` | Get the wallet's identity public key |
| `ordnet_sign_message` | Sign a message with the wallet key |
| `ordnet_verify_message` | Verify a signed message |

### Utilities (11 tools)

| Tool | Description |
|------|-------------|
| `ordnet_info` | Server information |
| `ordnet_content_types` | List supported content types |
| `ordnet_tx_simulate` | Decode/simulate a raw tx via ORDnet's own node |
| `ordnet_policy_set` | Set spend-policy limits (within operator ceilings) |
| `ordnet_policy_status` | Show the active spend policy and session total |
| `ordnet_index_health` | UTXO index health |
| `ordnet_address_watch` | Add an address to the watch index |
| `ordnet_bsvmap_inscribe` | Inscribe a BSVmap tile |
| `ordnet_inscribe_binary` | Inscribe binary content (e.g. an image) |
| `ordnet_tx_status` | Look up a transaction's status |
| `ordnet_price` | BSV price in fiat |

**Total: 45 tools.**

† Disabled on the remote HTTP transport: these two tools would move a
plaintext private key (WIF) over the network. Locally (stdio) they work;
remotely the server refuses them with an explanatory error. Use
`ordnet_wallet_init_env` on servers.

## Example: Create an HTML Inscription

```
User: Create a simple webpage saying "Hello from AI" and inscribe it on Bitcoin

AI: I'll create and inscribe this HTML content on the BSV blockchain.

1. First, let me initialize the wallet...
   [ordnet_wallet_init_env]
   ✓ Wallet initialized at 1ABC...

2. Creating the HTML inscription...
   [ordnet_inscribe_html] content="<html><body><h1>Hello from AI</h1></body></html>"
   
   ✓ Inscription successful!
   - TXID: abc123...
   - Inscription ID: abc123..._0
   - View: https://ordnet.io/view/abc123..._0
```

## Supported Content Types

- `text/html;charset=utf8` - HTML web pages
- `text/plain;charset=utf8` - Plain text
- `application/json` - JSON data
- `image/svg+xml` - SVG graphics
- `image/png` - PNG images
- `image/jpeg` - JPEG images
- `image/gif` - GIF animations
- `image/webp` - WebP images
- `audio/mpeg` - MP3 audio
- `video/mp4` - MP4 video
- `application/pdf` - PDF documents

## Supported Domain Extensions

### Universal
- `.sats`

### Chain-specific
- **BTC:** `.btc` `.ord` `.xbt` `.gm` `.unisat` `.x`
- **BSV:** `.bsv`
- **DOGE:** `.doge` `.shibe`
- **LTC:** `.ltc`
- **BCH:** `.bch`
- **BELLS:** `.bells`
- **And more...**

## Security Tiers

| Tier | Method | Security Level |
|------|--------|----------------|
| Environment | `ORDNET_WIF` env var | ⭐⭐⭐ Highest |
| Encrypted | AES-256-GCM encrypted store | ⭐⭐ Medium |
| Plaintext | Direct WIF input | ⭐ Lowest |

**Recommendation:** Always use environment variables in production.

## Development

```bash
# Clone and install
git clone https://github.com/ORDNET/ORDnet-MCP-Server.git
cd mcp-server
npm install

# Build
npm run build

# Run the audit regression tests (SSRF guard + spend policy).
# These run straight from source with Node's type stripping:
node --experimental-strip-types test/audit-2026-08-11.test.mjs

# Start server (stdio)
npm start

# Start server (HTTP)
TRANSPORT=http PORT=3000 npm start
```

## Transaction Structure

The inscription transaction follows the same output layout as the reference
inscriber (`ordmail-v10-standalone-026.html`). The service-fee outputs are the
11 entries of `SERVICE_FEE_OUTPUTS` in `src/constants.ts`:

```
Input:   UTXO(s) (user funds)
Output 0:  1 sat    - Inscription (OP_FALSE OP_IF "ord" ... OP_ENDIF + P2PKH)
Output 1:  0 sat    - OP_RETURN "ORDnet.io"
Output 2..12:        - 11 service-fee outputs (11,11,11,11,22,22,33,44,66,77,88 = 396 sats)
Output 13: Change (if > 546 sats)
```

The exact per-output amounts and addresses are listed under **Service Fees**
above and are the single source of truth (`SERVICE_FEE_OUTPUTS`). `ordnet_send`
omits the fee outputs entirely.

## API Endpoints Used

- **WhatsOnChain:** `https://api.whatsonchain.com/v1/bsv/main`
- **ORDnet Registry:** `https://registry.ordnet.io`
- **ORDnet Search:** `https://search.ordnet.io`

## License

MIT © ORDnet.io / Mister HHC B.V.

## Links

- Website: https://ordnet.io
- Documentation: this README is the reference for the MCP server. (https://docs.ordnet.io documents the ORD/apps suite, not this server.)
- GitHub: https://github.com/ordnet


## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ORDNET_WIF` | for wallet ops | Wallet private key (WIF). On HTTP transport this is the ONLY way to load a wallet. |
| `TRANSPORT` | no | `stdio` (default) or `http`. |
| `PORT` | no | HTTP port (default 3000). |
| `ORDNET_MCP_AUTH_TOKEN` | **yes, when TRANSPORT=http** | Bearer token (min. 32 chars). Server refuses to start without it. Generate: `openssl rand -hex 32`. |
| `ORDNET_POLICY_MAX_SATS_PER_TX` | recommended on http | Operator hard ceiling per transaction. `ordnet_policy_set` can tighten below it, never loosen above it. |
| `ORDNET_POLICY_MAX_SATS_PER_SESSION` | recommended on http | Operator hard ceiling per server session. |
| `ORDNET_UTXO_URL` | no | Base URL of the ordnet-utxo index (default `http://127.0.0.1:7002`). |
| `ORDNET_API` | no | Base URL of the ORDnet API used for price and proxy calls (default `https://api.ordnet.io`). |

## Known limitations

- Wallet and spend-policy state are per server **process**, not per client session. Run the HTTP transport for a single trusted agent/team behind the auth token, not as a public multi-tenant service.
- Balance and UTXO lookups use ORDnet's OWN address index (ordnet-utxo, port 7002, every UTXO node-verified) since v2.5; WhatsOnChain is a connectivity fallback only. New tools in v2.5: `ordnet_index_health`, `ordnet_address_watch`.
- UTXO selection skips 1-sat UTXOs as ordinal protection and combines multiple inputs when needed.
