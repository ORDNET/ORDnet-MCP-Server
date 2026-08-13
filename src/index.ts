#!/usr/bin/env node
/**
 * ORDnet MCP Server v3.1
 * 
 * Enable AI agents to create Web3 content on Bitcoin SV blockchain
 * 
 * Features:
 * - 45 tools for complete blockchain content creation
 * - 1SatOrdinals inscription support
 * - SNS/OPNS domain registration
 * - AES-256-GCM wallet security (3 tiers)
 * - Inscription output layout follows ordmail-v10-standalone-026.html
 * 
 * Service fees: 11+11+11+11+22+22+33+44+66+77+88 = 396 sats across 11 outputs
 *   (single source of truth: SERVICE_FEE_OUTPUTS in src/constants.ts)
 * 
 * @author ORDnet.io / Mister HHC B.V.
 * @license MIT
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';
import { timingSafeEqual } from 'crypto';
import { x402Quote, x402RetryWithProof } from './services/x402client.js';
import { z } from 'zod';

// Services
import {
  initializeWallet,
  getWalletAddress,
  isWalletInitialized,
  clearWallet,
  fetchBalance,
  fetchUTXOs,
  broadcastTransaction,
  validateAddress,
  generateWallet,
  fetchIndexHealth,
  watchAddress
} from './services/wallet.js';
import {
  getIdentityKey,
  signMessage,
  verifyMessage,
  deriveChildAddress
} from './services/brc100.js';

import {
  checkDomainAvailability,
  getDomainInfo,
  searchDomains,
  searchInscriptions,
  getInscription,
  getInscriptionContentUrl,
  getTransactionUrl,
  getViewerUrl
} from './services/ordnet.js';

// Network helpers: safeFetch vets attacker-supplied URLs, withTimeout is the
// bare timeout wrapper for calls to hosts we control. withTimeout was used at
// the price endpoint without ever being imported — a compile error that no CI
// existed to catch.
import { withTimeout } from './services/net.js';

import {
  encryptWIF,
  decryptWIF,
  getWIFFromEnv,
  detectSecurityTier,
  getWIFByTier,
  validatePassword,
  validateWIFFormat
} from './services/security.js';

// Transaction
import {
  calculateFeeEstimate,
  create1SatOrdinalTransaction,
  prepareInscription,
  getInscriptionId,
  createPaymentTx,
  createTransferTx
} from './transaction.js';

// Schemas
import {
  WalletInitSchema,
  WalletInitFromEnvSchema,
  GetBalanceSchema,
  GetUTXOsSchema,
  EstimateFeeSchema,
  CreateInscriptionSchema,
  BroadcastInscriptionSchema,
  CheckDomainSchema,
  GetDomainSchema,
  SearchDomainsSchema,
  RegisterDomainSchema,
  SearchInscriptionsSchema,
  GetInscriptionSchema,
  EncryptWalletSchema,
  ValidateAddressSchema,
  TxSimulateSchema,
  PolicySetSchema,
  PolicyStatusSchema,
  AddressWatchSchema,
  IndexHealthSchema,
  SendSchema,
  TransferSchema,
  BsvmapInscribeSchema,
  TxStatusSchema,
  PriceSchema,
  InscribeBase64Schema,
  SignMessageSchema,
  VerifyMessageSchema,
  DeriveChildSchema,
  IdentitySchema,
  X402QuoteSchema,
  X402FetchSchema
} from './schemas.js';

// V3 Pijler 3 — Agent Safety Layer
import {
  simulateTransaction,
  setPolicy,
  getPolicy,
  broadcastGuarded
} from './services/policy.js';

// Constants
import {
  TOTAL_SERVICE_FEES,
  SERVICE_FEE_OUTPUTS,
  CONTENT_TYPES,
  TX_CONSTANTS,
  API_ENDPOINTS
} from './constants.js';

import type { ContentType } from './types.js';

// ============================================================================
// v2.4 SECURITY: plaintext private-key material must never travel over the
// remote HTTP transport (request bodies, nginx logs, MCP clients). Tools that
// accept a raw WIF are disabled when TRANSPORT=http; use ORDNET_WIF on the
// server plus ordnet_wallet_init_env instead.
// ============================================================================
const IS_HTTP_TRANSPORT = (process.env.TRANSPORT || 'stdio') === 'http';

// v2.7 shared helpers for the new tools
function requireWallet(): { address: string } {
  if (!isWalletInitialized()) {
    throw new Error('Wallet not initialized. Call ordnet_wallet_init_env first.');
  }
  const address = getWalletAddress();
  if (!address) {
    throw new Error('Wallet address unavailable');
  }
  return { address };
}

function errorResponse(error: unknown, context: string) {
  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : context
      }, null, 2)
    }]
  };
}

function httpWifBlockedResponse() {
  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: false,
        error: 'This tool is disabled on the remote HTTP transport: it would send a plaintext private key over the network.',
        suggestion: 'Set ORDNET_WIF as an environment variable on the server and call ordnet_wallet_init_env instead.'
      }, null, 2)
    }]
  };
}

// ============================================================================
// Server Initialization
// ============================================================================

const server = new McpServer({
  name: 'ordnet-mcp-server',
  version: '3.1.0'
});

// ============================================================================
// TOOL CATEGORY 1: Wallet Management (6 tools)
// ============================================================================

server.registerTool(
  'ordnet_wallet_init',
  {
    title: 'Initialize ORDnet Wallet',
    description: `Initialize wallet from WIF private key for blockchain operations.

This is the first step before creating inscriptions. The wallet will be used for:
- Creating and signing inscription transactions
- Paying service fees (${TOTAL_SERVICE_FEES} sats across 11 outputs / 10 addresses)
- Receiving change from transactions

Security: WIF is held in memory only, not persisted. Use ordnet_wallet_init_env for production.

Args:
  - wif (string): WIF private key (starts with 5, K, or L, 51-52 chars)

Returns:
  { address: string, publicKey: string, balanceSatoshis: number }

Example:
  ordnet_wallet_init({ wif: "L1a2b3c4d5..." }) → Wallet initialized at 1ABC...`,
    inputSchema: WalletInitSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ wif }) => {
    if (IS_HTTP_TRANSPORT) return httpWifBlockedResponse();
    try {
      const wallet = initializeWallet(wif);
      const balance = await fetchBalance(wallet.address);
      
      const result = {
        success: true,
        address: wallet.address,
        publicKey: wallet.publicKey,
        balanceSatoshis: balance.total,
        balanceBSV: (balance.total / 100_000_000).toFixed(8)
      };
      
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    } catch (error) {
      return {
        content: [{ 
          type: 'text', 
          text: JSON.stringify({ 
            success: false, 
            error: error instanceof Error ? error.message : 'Unknown error',
            suggestion: 'Ensure the WIF is valid and starts with 5, K, or L'
          }) 
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_wallet_init_env',
  {
    title: 'Initialize Wallet from Environment',
    description: `Initialize wallet from environment variable (highest security tier).

Reads WIF from environment variable instead of passing it directly.
Recommended for production use.

Args:
  - envVarName (string): Environment variable name (default: ORDNET_WIF)

Returns:
  { address: string, balanceSatoshis: number }

Example:
  export ORDNET_WIF="L1a2b3c4..."
  ordnet_wallet_init_env({}) → Wallet initialized`,
    inputSchema: WalletInitFromEnvSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ envVarName = 'ORDNET_WIF' }) => {
    try {
      const wif = getWIFFromEnv(envVarName);
      if (!wif) {
        throw new Error(`Environment variable ${envVarName} not set`);
      }
      
      const wallet = initializeWallet(wif);
      const balance = await fetchBalance(wallet.address);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            securityTier: 'environment',
            address: wallet.address,
            balanceSatoshis: balance.total,
            balanceBSV: (balance.total / 100_000_000).toFixed(8)
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_wallet_status',
  {
    title: 'Get Wallet Status',
    description: `Check current wallet initialization status and balance.

Returns wallet address and balance if initialized.

Returns:
  { initialized: boolean, address?: string, balanceSatoshis?: number }`,
    inputSchema: {},
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async () => {
    const initialized = isWalletInitialized();
    const address = getWalletAddress();
    
    if (!initialized || !address) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            initialized: false,
            suggestion: 'Use ordnet_wallet_init or ordnet_wallet_init_env to initialize'
          })
        }]
      };
    }
    
    try {
      const balance = await fetchBalance(address);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            initialized: true,
            address,
            balanceSatoshis: balance.total,
            balanceBSV: (balance.total / 100_000_000).toFixed(8),
            confirmed: balance.confirmed,
            unconfirmed: balance.unconfirmed
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            initialized: true,
            address,
            balanceError: error instanceof Error ? error.message : 'Failed to fetch balance'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_wallet_balance',
  {
    title: 'Get BSV Balance',
    description: `Get balance for any BSV address.

Args:
  - address (string, optional): BSV address. Uses wallet address if not provided.

Returns:
  { address: string, confirmed: number, unconfirmed: number, total: number }`,
    inputSchema: GetBalanceSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ address }) => {
    try {
      const targetAddress = address || getWalletAddress();
      if (!targetAddress) {
        throw new Error('No address provided and wallet not initialized');
      }
      
      const balance = await fetchBalance(targetAddress);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            address: targetAddress,
            confirmed: balance.confirmed,
            unconfirmed: balance.unconfirmed,
            total: balance.total,
            bsv: (balance.total / 100_000_000).toFixed(8)
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_wallet_utxos',
  {
    title: 'Get Wallet UTXOs',
    description: `Get unspent transaction outputs (UTXOs) for an address.

Args:
  - address (string, optional): BSV address. Uses wallet address if not provided.
  - limit (number): Maximum UTXOs to return (default: 5)

Returns:
  { utxos: [{ txid, vout, satoshis }], count: number }`,
    inputSchema: GetUTXOsSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ address, limit = 5 }) => {
    try {
      const targetAddress = address || getWalletAddress();
      if (!targetAddress) {
        throw new Error('No address provided and wallet not initialized');
      }
      
      const utxos = await fetchUTXOs(targetAddress, limit);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            address: targetAddress,
            count: utxos.length,
            utxos: utxos.map(u => ({
              txid: u.txid,
              vout: u.vout,
              satoshis: u.satoshis
            }))
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_wallet_clear',
  {
    title: 'Clear Wallet',
    description: `Clear wallet from memory. Use when done with operations.

Returns:
  { cleared: true }`,
    inputSchema: {},
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async () => {
    clearWallet();
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ success: true, cleared: true })
      }]
    };
  }
);

// ============================================================================
// TOOL CATEGORY 2: Inscriptions (6 tools)
// ============================================================================

server.registerTool(
  'ordnet_fee_estimate',
  {
    title: 'Estimate Inscription Fee',
    description: `Calculate fee estimate for an inscription.

Service fees breakdown (per ordmail-v10-standalone-026.html):
- ordiBuilder / onnoBuilder / algoBuilder / colleagueI: 11 sats each
- protocol / colleagueD: 22 sats each
- monitor: 33 sats, indexer: 44 sats, partner: 66 sats
- founder: 77 sats, foundation: 88 sats
- Total: ${TOTAL_SERVICE_FEES} sats across 10 distinct addresses

Args:
  - contentSize (number): Size of content in bytes
  - feePerByte (number): Fee per byte (default: 0.15 = 150 sats/KB, miner fee floor 200 sats)

Returns:
  { estimatedTxSize, minerFee, serviceFee, totalCost, breakdown }`,
    inputSchema: EstimateFeeSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ contentSize, feePerByte = 0.15 }) => {
    const estimate = calculateFeeEstimate(contentSize, feePerByte);
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          ...estimate,
          note: `Service fees total ${TOTAL_SERVICE_FEES} sats, split across 11 outputs (see ordnet://fees)`
        }, null, 2)
      }]
    };
  }
);

server.registerTool(
  'ordnet_inscribe_prepare',
  {
    title: 'Prepare Inscription',
    description: `Prepare an inscription transaction without broadcasting.

Creates a signed transaction ready for broadcast. Returns the raw hex
and fee breakdown for review before broadcasting.

Args:
  - content (string): Content to inscribe (HTML, text, JSON, etc.)
  - contentType (string): MIME type (default: text/html;charset=utf8)
  - feePerByte (number): Fee per byte (default: 0.2)

Returns:
  { rawHex, txid, feeEstimate, inscriptionId }

Requires: Wallet must be initialized first.`,
    inputSchema: CreateInscriptionSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false
    }
  },
  async ({ content, contentType = 'text/html;charset=utf8', feePerByte = 0.15 }) => {
    try {
      if (!isWalletInitialized()) {
        throw new Error('Wallet not initialized. Call ordnet_wallet_init first.');
      }
      
      const result = await prepareInscription(content, contentType as ContentType, feePerByte);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid: result.txid,
            inscriptionId: getInscriptionId(result.txid),
            rawHex: result.rawHex,
            feeEstimate: result.feeEstimate,
            contentSize: content.length,
            contentType,
            note: 'Transaction prepared but NOT broadcast. Use ordnet_inscribe_broadcast to broadcast.'
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_inscribe_broadcast',
  {
    title: 'Broadcast Inscription',
    description: `Broadcast a prepared inscription transaction to the BSV network.

WARNING: This action is IRREVERSIBLE. The transaction will be permanently
recorded on the blockchain.

Args:
  - rawHex (string): Raw transaction hex from ordnet_inscribe_prepare

Returns:
  { txid, inscriptionId, viewUrl, transactionUrl }`,
    inputSchema: BroadcastInscriptionSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ rawHex }) => {
    try {
      // V3 safety layer: enforce spend policy (no-op when no limits are set)
      // v3.0.1: pass own address so change doesn't count against the limit
      // K8: single guarded path. The raw hex was prepared elsewhere, so the
      // miner fee is not known here; enforcePolicy still counts the outputs.
      const { txid } = await broadcastGuarded(
        broadcastTransaction, rawHex, getWalletAddress() ?? undefined
      );
      const inscriptionId = getInscriptionId(txid);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            inscriptionId,
            viewUrl: getViewerUrl(inscriptionId),
            contentUrl: getInscriptionContentUrl(inscriptionId),
            transactionUrl: getTransactionUrl(txid),
            note: 'Inscription successfully broadcast to BSV network!'
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Broadcast failed'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_inscribe_html',
  {
    title: 'Inscribe HTML Content',
    description: `Create and broadcast an HTML inscription in one step.

Convenience tool that prepares and broadcasts an HTML inscription.

Args:
  - content (string): HTML content to inscribe
  - feePerByte (number): Fee per byte (default: 0.2)

Returns:
  { txid, inscriptionId, viewUrl }

Requires: Wallet must be initialized.`,
    inputSchema: CreateInscriptionSchema.omit({ contentType: true }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ content, feePerByte = 0.15 }) => {
    try {
      if (!isWalletInitialized()) {
        throw new Error('Wallet not initialized. Call ordnet_wallet_init first.');
      }
      
      const prepared = await prepareInscription(content, CONTENT_TYPES.HTML, feePerByte);
      const { txid } = await broadcastGuarded(
        broadcastTransaction, prepared.rawHex, getWalletAddress() ?? undefined, prepared.feeEstimate.minerFee
      );
      const inscriptionId = getInscriptionId(txid);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            inscriptionId,
            viewUrl: getViewerUrl(inscriptionId),
            contentUrl: getInscriptionContentUrl(inscriptionId),
            transactionUrl: getTransactionUrl(txid),
            fee: prepared.feeEstimate
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_inscribe_json',
  {
    title: 'Inscribe JSON Content',
    description: `Create and broadcast a JSON inscription in one step.

Args:
  - content (string): JSON content to inscribe
  - feePerByte (number): Fee per byte (default: 0.2)

Returns:
  { txid, inscriptionId, viewUrl }`,
    inputSchema: CreateInscriptionSchema.omit({ contentType: true }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ content, feePerByte = 0.15 }) => {
    try {
      if (!isWalletInitialized()) {
        throw new Error('Wallet not initialized. Call ordnet_wallet_init first.');
      }
      
      // Validate JSON
      try {
        JSON.parse(content);
      } catch {
        throw new Error('Invalid JSON content');
      }
      
      const prepared = await prepareInscription(content, CONTENT_TYPES.JSON, feePerByte);
      const { txid } = await broadcastGuarded(
        broadcastTransaction, prepared.rawHex, getWalletAddress() ?? undefined, prepared.feeEstimate.minerFee
      );
      const inscriptionId = getInscriptionId(txid);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            inscriptionId,
            viewUrl: getViewerUrl(inscriptionId),
            contentUrl: getInscriptionContentUrl(inscriptionId),
            transactionUrl: getTransactionUrl(txid)
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_inscribe_text',
  {
    title: 'Inscribe Plain Text',
    description: `Create and broadcast a plain text inscription in one step.

Args:
  - content (string): Text content to inscribe
  - feePerByte (number): Fee per byte (default: 0.2)

Returns:
  { txid, inscriptionId, viewUrl }`,
    inputSchema: CreateInscriptionSchema.omit({ contentType: true }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ content, feePerByte = 0.15 }) => {
    try {
      if (!isWalletInitialized()) {
        throw new Error('Wallet not initialized. Call ordnet_wallet_init first.');
      }
      
      const prepared = await prepareInscription(content, CONTENT_TYPES.TEXT, feePerByte);
      const { txid } = await broadcastGuarded(
        broadcastTransaction, prepared.rawHex, getWalletAddress() ?? undefined, prepared.feeEstimate.minerFee
      );
      const inscriptionId = getInscriptionId(txid);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            inscriptionId,
            viewUrl: getViewerUrl(inscriptionId),
            contentUrl: getInscriptionContentUrl(inscriptionId),
            transactionUrl: getTransactionUrl(txid)
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

// ============================================================================
// TOOL CATEGORY 3: Domains (6 tools)
// ============================================================================

server.registerTool(
  'ordnet_domain_check',
  {
    title: 'Check Domain Availability',
    description: `Check if a domain name is available for registration.

Args:
  - name (string): Domain name without extension (e.g., "myname")
  - extension (string): Domain extension (default: .sats)

Returns:
  { available: boolean, owner?: string, inscriptionId?: string }`,
    inputSchema: CheckDomainSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ name, extension = '.sats' }) => {
    try {
      const result = await checkDomainAvailability(name, extension);
      const fullName = `${name}${extension}`;
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            domain: fullName,
            ...result
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_domain_info',
  {
    title: 'Get Domain Information',
    description: `Get detailed information about a domain.

Args:
  - fullName (string): Full domain name (e.g., "myname.sats")

Returns:
  { name, extension, owner, inscriptionId, genesisHeight, protocol }`,
    inputSchema: GetDomainSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ fullName }) => {
    try {
      const info = await getDomainInfo(fullName);
      
      if (!info) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: true,
              found: false,
              domain: fullName
            })
          }]
        };
      }
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            found: true,
            ...info
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_domain_search',
  {
    title: 'Search Domains',
    description: `Search for registered domains by name prefix.

Args:
  - query (string): Search query
  - limit (number): Maximum results (default: 20)

Returns:
  { domains: [{ name, owner, inscriptionId }], count }`,
    inputSchema: SearchDomainsSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ query, limit = 20 }) => {
    try {
      const domains = await searchDomains(query, limit);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            query,
            count: domains.length,
            domains
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_domain_register',
  {
    title: 'Register Domain',
    description: `Register a new SNS/OPNS domain on the blockchain.

Creates and broadcasts a domain registration inscription.

Args:
  - name (string): Domain name without extension
  - extension (string): Domain extension (default: .sats)
  - protocol (string): Registration protocol: sns or opns (default: sns)
  - feePerByte (number): Fee per byte (default: 0.2)

Returns:
  { txid, inscriptionId, domain }

Requires: Wallet must be initialized.`,
    inputSchema: RegisterDomainSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ name, extension = '.sats', protocol = 'sns', feePerByte = 0.15 }) => {
    try {
      if (!isWalletInitialized()) {
        throw new Error('Wallet not initialized. Call ordnet_wallet_init first.');
      }
      
      const fullName = `${name}${extension}`;
      
      // Check availability first
      const availability = await checkDomainAvailability(name, extension);
      if (!availability.available) {
        throw new Error(`Domain ${fullName} is already registered`);
      }
      
      // Create registration JSON
      const registrationJson = JSON.stringify({
        p: protocol,
        op: 'reg',
        name: fullName
      });
      
      // Inscribe
      const prepared = await prepareInscription(registrationJson, CONTENT_TYPES.JSON, feePerByte);
      const { txid } = await broadcastGuarded(
        broadcastTransaction, prepared.rawHex, getWalletAddress() ?? undefined, prepared.feeEstimate.minerFee
      );
      const inscriptionId = getInscriptionId(txid);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            inscriptionId,
            domain: fullName,
            protocol,
            transactionUrl: getTransactionUrl(txid),
            note: 'Domain registration broadcast! It may take a few minutes to be indexed.'
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_domain_register_sns',
  {
    title: 'Register SNS Domain',
    description: `Quick registration of an SNS domain (.sats, .btc, etc).

Args:
  - name (string): Domain name without extension
  - extension (string): Extension (default: .sats)
  - feePerByte (number): Fee per byte (default: 0.2)

Returns:
  { txid, inscriptionId, domain }`,
    inputSchema: RegisterDomainSchema.omit({ protocol: true }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ name, extension = '.sats', feePerByte = 0.15 }) => {
    try {
      if (!isWalletInitialized()) {
        throw new Error('Wallet not initialized');
      }
      
      const fullName = `${name}${extension}`;
      const availability = await checkDomainAvailability(name, extension);
      
      if (!availability.available) {
        throw new Error(`Domain ${fullName} already registered`);
      }
      
      const registrationJson = JSON.stringify({
        p: 'sns',
        op: 'reg',
        name: fullName
      });
      
      const prepared = await prepareInscription(registrationJson, CONTENT_TYPES.JSON, feePerByte);
      const { txid } = await broadcastGuarded(
        broadcastTransaction, prepared.rawHex, getWalletAddress() ?? undefined, prepared.feeEstimate.minerFee
      );
      const inscriptionId = getInscriptionId(txid);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            inscriptionId,
            domain: fullName,
            protocol: 'sns',
            transactionUrl: getTransactionUrl(txid)
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_domain_register_opns',
  {
    title: 'Register OPNS Domain',
    description: `Quick registration of an OPNS domain.

Args:
  - name (string): Domain name without extension
  - extension (string): Extension (default: .sats)
  - feePerByte (number): Fee per byte (default: 0.2)

Returns:
  { txid, inscriptionId, domain }`,
    inputSchema: RegisterDomainSchema.omit({ protocol: true }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ name, extension = '.sats', feePerByte = 0.15 }) => {
    try {
      if (!isWalletInitialized()) {
        throw new Error('Wallet not initialized');
      }
      
      const fullName = `${name}${extension}`;
      const availability = await checkDomainAvailability(name, extension);
      
      if (!availability.available) {
        throw new Error(`Domain ${fullName} already registered`);
      }
      
      const registrationJson = JSON.stringify({
        p: 'opns',
        op: 'reg',
        name: fullName
      });
      
      const prepared = await prepareInscription(registrationJson, CONTENT_TYPES.JSON, feePerByte);
      const { txid } = await broadcastGuarded(
        broadcastTransaction, prepared.rawHex, getWalletAddress() ?? undefined, prepared.feeEstimate.minerFee
      );
      const inscriptionId = getInscriptionId(txid);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            inscriptionId,
            domain: fullName,
            protocol: 'opns',
            transactionUrl: getTransactionUrl(txid)
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

// ============================================================================
// TOOL CATEGORY 4: Search & Lookup (4 tools)
// ============================================================================

server.registerTool(
  'ordnet_search_inscriptions',
  {
    title: 'Search Inscriptions',
    description: `Search for inscriptions on the BSV blockchain.

Args:
  - query (string): Search query
  - contentType (string, optional): Filter by content type
  - limit (number): Maximum results (default: 20)

Returns:
  { inscriptions: [...], count }`,
    inputSchema: SearchInscriptionsSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ query, contentType, limit = 20 }) => {
    try {
      const results = await searchInscriptions(query, contentType, limit);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            query,
            count: results.length,
            inscriptions: results
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_get_inscription',
  {
    title: 'Get Inscription Details',
    description: `Get detailed information about a specific inscription.

Args:
  - inscriptionId (string): Inscription ID (format: txid_outputIndex)

Returns:
  { inscriptionId, contentType, contentSize, owner, ... }`,
    inputSchema: GetInscriptionSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ inscriptionId }) => {
    try {
      const result = await getInscription(inscriptionId);
      
      if (!result) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: true,
              found: false,
              inscriptionId
            })
          }]
        };
      }
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            found: true,
            ...result,
            viewUrl: getViewerUrl(inscriptionId),
            contentUrl: getInscriptionContentUrl(inscriptionId)
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_get_content_url',
  {
    title: 'Get Content URL',
    description: `Get the URL to view inscription content.

Args:
  - inscriptionId (string): Inscription ID

Returns:
  { inscriptionId, contentUrl, viewUrl, transactionUrl }`,
    inputSchema: GetInscriptionSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ inscriptionId }) => {
    const txid = inscriptionId.split('_')[0];
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          inscriptionId,
          contentUrl: getInscriptionContentUrl(inscriptionId),
          viewUrl: getViewerUrl(inscriptionId),
          transactionUrl: getTransactionUrl(txid)
        }, null, 2)
      }]
    };
  }
);

server.registerTool(
  'ordnet_validate_address',
  {
    title: 'Validate BSV Address',
    description: `Validate a BSV address format.

Args:
  - address (string): BSV address to validate

Returns:
  { valid: boolean, address }`,
    inputSchema: ValidateAddressSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ address }) => {
    const valid = validateAddress(address);
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          address,
          valid
        })
      }]
    };
  }
);

// ============================================================================
// TOOL CATEGORY 5: Security (4 tools)
// ============================================================================

server.registerTool(
  'ordnet_security_encrypt_wallet',
  {
    title: 'Encrypt Wallet',
    description: `Encrypt a WIF private key with AES-256-GCM.

Use this to create an encrypted wallet that can be stored safely.
The encrypted data can later be decrypted with ordnet_wallet_init with the password.

Args:
  - wif (string): WIF private key to encrypt
  - password (string): Strong password (min 12 chars)

Returns:
  { encrypted: { iv, data, tag, salt } }`,
    inputSchema: EncryptWalletSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ wif, password }) => {
    if (IS_HTTP_TRANSPORT) return httpWifBlockedResponse();
    try {
      // Validate password
      const passwordCheck = validatePassword(password);
      if (!passwordCheck.valid) {
        throw new Error(`Weak password: ${passwordCheck.errors.join(', ')}`);
      }
      
      // Validate WIF
      if (!validateWIFFormat(wif)) {
        throw new Error('Invalid WIF format');
      }
      
      const encrypted = encryptWIF(wif, password);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            encrypted,
            note: 'Store this encrypted data safely. You will need the password to decrypt it.'
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Encryption failed'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_security_tier',
  {
    title: 'Get Security Tier',
    description: `Check the current wallet security tier.

Tiers (highest to lowest):
1. environment - WIF from environment variable
2. encrypted - WIF from encrypted store
3. plaintext - WIF provided directly (not recommended)

Returns:
  { tier, envVarSet, recommendation }`,
    inputSchema: {},
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async () => {
    const tier = detectSecurityTier();
    const envVarSet = !!process.env.ORDNET_WIF;
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          tier,
          envVarSet,
          recommendation: envVarSet 
            ? 'Using environment variable (recommended)'
            : 'Set ORDNET_WIF environment variable for better security'
        }, null, 2)
      }]
    };
  }
);

server.registerTool(
  'ordnet_security_validate_password',
  {
    title: 'Validate Password Strength',
    description: `Check if a password meets security requirements.

Requirements:
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

Args:
  - password (string): Password to validate

Returns:
  { valid: boolean, errors: string[] }`,
    inputSchema: z.object({
      password: z.string().describe('Password to validate')
    }).strict(),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ password }: { password: string }) => {
    const result = validatePassword(password);
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          ...result
        })
      }]
    };
  }
);

server.registerTool(
  'ordnet_generate_wallet',
  {
    title: 'Generate New Wallet',
    description: `Generate a new random BSV wallet.

WARNING: Store the WIF securely! It cannot be recovered if lost.

Returns:
  { wif, address }`,
    inputSchema: {},
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false
    }
  },
  async () => {
    // H9 (external audit, 11 Aug 2026) — this returns a freshly minted WIF in
    // the tool output. Over the remote HTTP transport that is a plaintext
    // private key crossing the network, exactly what the IS_HTTP_TRANSPORT
    // guard on ordnet_wallet_init and ordnet_security_encrypt_wallet exists to
    // prevent. The guard was simply missing here. Generate keys locally
    // (stdio), never over HTTP.
    if (IS_HTTP_TRANSPORT) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: 'This tool is disabled on the remote HTTP transport: it would return a freshly generated private key (WIF) over the network.',
            suggestion: 'Generate the key locally with the server on the stdio transport, or use any offline BSV key generator, then provide it via ORDNET_WIF + ordnet_wallet_init_env.'
          }, null, 2)
        }]
      };
    }
    const wallet = generateWallet();
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          ...wallet,
          warning: 'SAVE THE WIF SECURELY! It cannot be recovered if lost.'
        }, null, 2)
      }]
    };
  }
);

// ============================================================================
// TOOL CATEGORY 6: Payments, identity & utilities (19 tools)
// ============================================================================

server.registerTool(
  'ordnet_info',
  {
    title: 'ORDnet Server Info',
    description: `Get information about the ORDnet MCP server.

Returns server version, capabilities, and service fee information.`,
    inputSchema: {},
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async () => {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          name: 'ORDnet MCP Server',
          version: '3.1.0',
          description: 'Enable AI agents to create Web3 content on Bitcoin SV blockchain',
          author: 'ORDnet.io / Mister HHC B.V.',
          serviceFees: {
            total: TOTAL_SERVICE_FEES,
            outputs: SERVICE_FEE_OUTPUTS
          },
          toolCategories: {
            wallet: 6,
            inscriptions: 6,
            domains: 6,
            search: 4,
            security: 4,
            payments: 5,      // send, transfer, x402_quote, x402_fetch, derive_payment_address
            identity: 3,      // identity, sign_message, verify_message
            utilities: 11     // info, content_types, tx_simulate, policy_set, policy_status,
                              // index_health, address_watch, bsvmap_inscribe, inscribe_binary,
                              // tx_status, price
          },
          totalTools: 45,
          supportedContentTypes: Object.values(CONTENT_TYPES),
          links: {
            website: 'https://ordnet.io',
            documentation: 'https://docs.ordnet.io',
            github: 'https://github.com/ordnet'
          }
        }, null, 2)
      }]
    };
  }
);

server.registerTool(
  'ordnet_content_types',
  {
    title: 'List Supported Content Types',
    description: `Get list of all supported content types for inscriptions.

Returns:
  { contentTypes: [...] }`,
    inputSchema: {},
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async () => {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          contentTypes: [
            { type: CONTENT_TYPES.HTML, description: 'HTML web pages' },
            { type: CONTENT_TYPES.TEXT, description: 'Plain text' },
            { type: CONTENT_TYPES.JSON, description: 'JSON data' },
            { type: CONTENT_TYPES.SVG, description: 'SVG vector graphics' },
            { type: CONTENT_TYPES.PNG, description: 'PNG images' },
            { type: CONTENT_TYPES.JPEG, description: 'JPEG images' },
            { type: CONTENT_TYPES.GIF, description: 'GIF images' },
            { type: CONTENT_TYPES.WEBP, description: 'WebP images' },
            { type: CONTENT_TYPES.MP3, description: 'MP3 audio' },
            { type: CONTENT_TYPES.MP4, description: 'MP4 video' },
            { type: CONTENT_TYPES.PDF, description: 'PDF documents' }
          ]
        }, null, 2)
      }]
    };
  }
);

// ============================================================================
// V3 Pijler 3 — Agent Safety Layer
// ============================================================================

server.registerTool(
  'ordnet_tx_simulate',
  {
    title: 'Simulate Transaction (Dry Run)',
    description: `Decode and inspect a raw transaction via ORDnet's OWN node WITHOUT broadcasting it.

Use this BEFORE ordnet_inscribe_broadcast to verify exactly what a transaction
will do: destinations, amounts, and safety warnings (e.g. 1-satoshi outputs
that are likely ordinals/inscriptions).

Args:
  - rawHex (string): Raw transaction hex to simulate

Returns:
  { txid, sizeBytes, outputCount, totalOutputSats, outputs[], warnings[] }`,
    inputSchema: TxSimulateSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ rawHex }) => {
    try {
      const sim = await simulateTransaction(rawHex);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ success: true, ...sim }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_policy_set',
  {
    title: 'Set Spend Policy',
    description: `Configure spend limits for this server session (agent safety layer).

When any limit is set, every broadcast is first simulated via ORDnet's own
node and BLOCKED if it would exceed a limit (fail-closed). When no limits
are set, broadcasts behave exactly as before.

Limits apply to the TOTAL output value of a transaction, including change
back to the agent's own wallet (a conservative upper bound).

Args:
  - maxSatsPerTx (number|null, optional): Max output sats per transaction; null removes the limit
  - maxSatsPerSession (number|null, optional): Max cumulative output sats this session; null removes the limit
  - resetSession (boolean, optional): Reset the session spend counter

Returns:
  The active policy after applying changes.`,
    inputSchema: PolicySetSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false
    }
  },
  async ({ maxSatsPerTx, maxSatsPerSession, resetSession }) => {
    const updated = setPolicy({ maxSatsPerTx, maxSatsPerSession, resetSession });
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ success: true, policy: updated }, null, 2)
      }]
    };
  }
);

server.registerTool(
  'ordnet_policy_status',
  {
    title: 'Get Spend Policy Status',
    description: `Show the active spend policy and session totals.

Returns:
  { maxSatsPerTx, maxSatsPerSession, spentThisSession, broadcastCount }`,
    inputSchema: PolicyStatusSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async () => {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ success: true, policy: getPolicy() }, null, 2)
      }]
    };
  }
);


// ============================================================================
// v2.5: ORDnet UTXO Index tools (own address index on port 7002)
// ============================================================================

server.registerTool(
  'ordnet_index_health',
  {
    title: 'ORDnet UTXO Index Health',
    description: `Check the health and sync status of ORDnet's own address/UTXO index (ordnet-utxo).

This index is the PRIMARY source for balance and UTXO lookups since v2.5 —
every UTXO in it has been individually verified by ORDnet's own BSV node.
WhatsOnChain is only used as a connectivity fallback.

Returns:
  { status, index_height, node_height, in_sync }`,
    inputSchema: IndexHealthSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async () => {
    try {
      const h = await fetchIndexHealth();
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            ...h,
            in_sync: h.index_height >= h.node_height
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Index health check failed',
            note: 'Wallet operations fall back to WhatsOnChain while the index is unavailable.'
          }, null, 2)
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_address_watch',
  {
    title: 'Watch Address in ORDnet Index',
    description: `Register a BSV address in ORDnet's own UTXO index watchlist.

The index seeds the address immediately (WhatsOnChain as outpoint hint, every
UTXO verified by ORDnet's own node) and then tracks it in real time via the
tip-follower. Unknown addresses are also auto-registered on their first
balance/UTXO query; this tool lets an agent pre-register addresses so that
first query is instant.

Args:
  - address (string): BSV address to watch
  - label (string, optional): label for the watchlist entry (default: "mcp")

Returns:
  Watchlist registration result from the index.`,
    inputSchema: AddressWatchSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async ({ address, label }) => {
    try {
      const result = await watchAddress(address, label);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ success: true, result }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Watch registration failed'
          }, null, 2)
        }]
      };
    }
  }
);


// ============================================================================
// v2.7: Payments & transfers — the core of "AI agents transact via ORDnet"
// ============================================================================

server.registerTool(
  'ordnet_send',
  {
    title: 'Send BSV Payment',
    description: `Send a plain BSV payment (P2PKH) from the initialized wallet.

THE core tool for agent payments: miner fee only (0.15 sat/byte, min 200 sats),
NO service fees — micropayments stay lean. Optional OP_RETURN data lets you
attach a payment reference (e.g. an x402 invoice ID).

Safety: spend policy (ordnet_policy_status) is enforced; 1-sat ordinal UTXOs
are never used as funding.

Args:
  - to (string): recipient BSV address
  - satoshis (number): amount in satoshis
  - opReturn (string, optional): OP_RETURN payload / payment reference

Returns:
  { txid, satoshis, minerFee, change, transactionUrl }`,
    inputSchema: SendSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ to, satoshis, opReturn }) => {
    try {
      const wallet = requireWallet();
      const utxos = await fetchUTXOs(wallet.address);
      const payment = createPaymentTx(utxos, [{ address: to, satoshis }], opReturn);
      const { txid } = await broadcastGuarded(
        broadcastTransaction, payment.rawHex, wallet.address, payment.minerFee
      );
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            to,
            satoshis,
            minerFee: payment.minerFee,
            change: payment.change,
            opReturn: opReturn || null,
            transactionUrl: getTransactionUrl(txid)
          }, null, 2)
        }]
      };
    } catch (error) {
      return errorResponse(error, 'Payment failed');
    }
  }
);

server.registerTool(
  'ordnet_transfer',
  {
    title: 'Transfer Ordinal or Domain',
    description: `Transfer an inscription (ordinal, .web3/SNS/OPNS domain, BSVmap tile) to another address.

1SatOrdinals semantics: the inscription outpoint becomes input 0 and the 1-sat
output to the recipient becomes output 0 — the sat carries the inscription.
The outpoint is verified as unspent via ORDnet's own node before building.
Miner fee only.

Args:
  - inscriptionTxid (string): txid of the inscription outpoint
  - inscriptionVout (number): output index (usually 0)
  - to (string): recipient BSV address

Returns:
  { txid, transferred, to, minerFee, transactionUrl }`,
    inputSchema: TransferSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ inscriptionTxid, inscriptionVout, to }) => {
    try {
      const wallet = requireWallet();
      // Verify the outpoint via our own node (gettxout through api.ordnet.io)
      const txoutResp = await fetch(`${API_ENDPOINTS.ORDNET_API}/v1/bsv/txout/${inscriptionTxid}/${inscriptionVout}`);
      const txout = await txoutResp.json().catch(() => null) as any;
      if (!txout || txout.error || txout === null || typeof txout.value !== 'number') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: false,
              error: 'Inscription outpoint not found or already spent (verified via own node)',
              outpoint: `${inscriptionTxid}:${inscriptionVout}`
            }, null, 2)
          }]
        };
      }
      const ordinalSats = Math.round(txout.value * 1e8);
      const utxos = await fetchUTXOs(wallet.address);
      const transfer = createTransferTx(
        { txid: inscriptionTxid, vout: inscriptionVout, satoshis: ordinalSats },
        to,
        utxos
      );
      const { txid } = await broadcastGuarded(
        broadcastTransaction, transfer.rawHex, wallet.address, transfer.minerFee
      );
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            transferred: `${inscriptionTxid}:${inscriptionVout}`,
            to,
            minerFee: transfer.minerFee,
            transactionUrl: getTransactionUrl(txid)
          }, null, 2)
        }]
      };
    } catch (error) {
      return errorResponse(error, 'Transfer failed');
    }
  }
);

server.registerTool(
  'ordnet_bsvmap_inscribe',
  {
    title: 'Claim BSVmap Tile',
    description: `Claim a BSVmap tile by inscribing "<tile>.bsvmap" (text/plain), following the
bitmap convention on BSV. Tiles 0-999999 map to the 1M-tile BSVmap grid.

Note: first-is-first — if the tile was already claimed on-chain, your
inscription will not make you the owner. Check bsvmap.io first.

Args:
  - tile (number): tile number 0-999999
  - feePerByte (number, optional): default 0.15

Returns prepared inscription; broadcast with ordnet_inscribe_broadcast.`,
    inputSchema: BsvmapInscribeSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ tile, feePerByte = 0.15 }) => {
    try {
      requireWallet();
      const content = `${tile}.bsvmap`;
      const prepared = await prepareInscription(content, CONTENT_TYPES.TEXT, feePerByte);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            tile,
            inscription: content,
            ...prepared,
            note: 'Broadcast with ordnet_inscribe_broadcast to claim the tile.'
          }, null, 2)
        }]
      };
    } catch (error) {
      return errorResponse(error, 'BSVmap prepare failed');
    }
  }
);

server.registerTool(
  'ordnet_inscribe_binary',
  {
    title: 'Inscribe Binary Content',
    description: `Prepare an inscription for BINARY content (images, audio, video, PDF) from base64.

Bytes are inscribed untouched — use this instead of ordnet_inscribe_prepare for
anything that is not text. Supported: image/png, image/jpeg, image/gif,
image/webp, image/svg+xml, audio/mpeg, video/mp4, application/pdf.

Args:
  - contentBase64 (string): base64-encoded content
  - contentType (string): MIME type, e.g. image/png
  - feePerByte (number, optional): default 0.15

Returns prepared inscription; broadcast with ordnet_inscribe_broadcast.`,
    inputSchema: InscribeBase64Schema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ contentBase64, contentType, feePerByte = 0.15 }) => {
    try {
      requireWallet();
      let buf: Buffer;
      try {
        buf = Buffer.from(contentBase64, 'base64');
        if (buf.length === 0) throw new Error('empty');
      } catch {
        return errorResponse(new Error('Invalid base64 content'), 'Invalid base64');
      }
      const prepared = await prepareInscription(buf, contentType as any, feePerByte);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            contentType,
            contentSizeBytes: buf.length,
            ...prepared,
            note: 'Broadcast with ordnet_inscribe_broadcast.'
          }, null, 2)
        }]
      };
    } catch (error) {
      return errorResponse(error, 'Binary inscription prepare failed');
    }
  }
);

server.registerTool(
  'ordnet_tx_status',
  {
    title: 'Transaction Status',
    description: `Check the status and confirmations of a transaction via ORDnet's own node.

Essential after ordnet_send / ordnet_inscribe_broadcast / ordnet_transfer:
poll this to see your transaction confirm.

Args:
  - txid (string): transaction ID

Returns:
  { txid, found, confirmations, blockhash, blocktime }`,
    inputSchema: TxStatusSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ txid }) => {
    try {
      const resp = await fetch(`${API_ENDPOINTS.ORDNET_API}/v1/bsv/tx/${txid}`);
      const data = await resp.json() as any;
      if (data && typeof data === 'object' && !data.error) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: true,
              txid,
              found: true,
              confirmations: data.confirmations ?? 0,
              inMempool: !data.blockhash,
              blockhash: data.blockhash || null,
              blocktime: data.blocktime || null
            }, null, 2)
          }]
        };
      }
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            txid,
            found: false,
            note: 'Transaction not found by our node (not broadcast, or pruned mempool).'
          }, null, 2)
        }]
      };
    } catch (error) {
      return errorResponse(error, 'Status check failed');
    }
  }
);

server.registerTool(
  'ordnet_price',
  {
    title: 'BSV Price',
    description: `Get the current BSV price in fiat, via ORDnet's own CoinGecko proxy.

Lets an agent convert satoshis to USD/EUR before spending.

Args:
  - currencies (string, optional): comma-separated, default "usd,eur"

Returns:
  { bsv: { usd, eur, ... }, satsPerUsd }`,
    inputSchema: PriceSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ currencies = 'usd,eur' }) => {
    try {
      const url = `${API_ENDPOINTS.ORDNET_API}/proxy/coingecko/api/v3/simple/price?ids=bitcoin-cash-sv&vs_currencies=${encodeURIComponent(currencies)}`;
      const resp = await withTimeout(url);
      const data = await resp.json() as any;
      const prices = data['bitcoin-cash-sv'] || data['bitcoin-sv'] || null;
      if (!prices) {
        return errorResponse(new Error('Price data unavailable'), 'Price lookup failed');
      }
      const usd = prices.usd;
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            bsv: prices,
            satsPerUsd: usd ? Math.round(1e8 / usd) : null
          }, null, 2)
        }]
      };
    } catch (error) {
      return errorResponse(error, 'Price lookup failed');
    }
  }
);


// ============================================================================
// v2.7: MCP Prompts — discoverable workflows for agents (prompts/list)
// ============================================================================

server.registerPrompt(
  'inscribe-website',
  {
    title: 'Inscribe a website on BSV',
    description: 'Guided workflow: put an HTML page permanently on the BSV blockchain',
    argsSchema: { topic: z.string().describe('What the page should be about') }
  },
  ({ topic }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Create a single-file HTML page about "${topic}" (inline CSS, no external assets), then: 1) check my wallet with ordnet_wallet_status and ordnet_wallet_balance, 2) estimate cost with ordnet_fee_estimate, 3) prepare with ordnet_inscribe_html, 4) broadcast with ordnet_inscribe_broadcast, 5) confirm with ordnet_tx_status and give me the view URL.`
      }
    }]
  })
);

server.registerPrompt(
  'register-domain',
  {
    title: 'Register a Web3 domain',
    description: 'Guided workflow: check availability and register an SNS/OPNS domain',
    argsSchema: { domain: z.string().describe('Domain name including TLD, e.g. myname.sats') }
  },
  ({ domain }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Register the domain "${domain}" for me: 1) verify availability with ordnet_domain_check, 2) if taken, suggest 3 alternatives via ordnet_domain_search, 3) if available, register with the appropriate ordnet_domain_register_* tool, broadcast, and confirm with ordnet_tx_status.`
      }
    }]
  })
);

server.registerPrompt(
  'agent-payment',
  {
    title: 'Pay another agent or service',
    description: 'Guided workflow: send a BSV payment with a reference, safely',
    argsSchema: {
      recipient: z.string().describe('Recipient BSV address'),
      amount: z.string().describe('Amount in satoshis'),
      reference: z.string().optional().describe('Payment reference (e.g. invoice or x402 ID)')
    }
  },
  ({ recipient, amount, reference }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Send ${amount} sats to ${recipient}${reference ? ` with reference "${reference}" in OP_RETURN` : ''}: 1) check ordnet_policy_status and ordnet_wallet_balance first, 2) convert the amount to USD with ordnet_price and report it, 3) send with ordnet_send, 4) poll ordnet_tx_status until seen by the node and report the txid.`
      }
    }]
  })
);

// ============================================================================
// v3.0: BRC-100 aligned identity, signing & payment-key derivation
// ============================================================================

server.registerTool(
  'ordnet_identity',
  {
    title: 'Get BRC-100 Identity Key',
    description: `Return the wallet's BRC-100 identity: its public key and address.

This is the agent's on-chain identity — counterparties can use the public key
to verify signatures (ordnet_verify_message) and to confirm the agent controls
the address. Requires an initialized wallet.

Returns:
  { publicKey, address }`,
    inputSchema: IdentitySchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  async () => {
    try {
      requireWallet();
      return { content: [{ type: 'text', text: JSON.stringify({ success: true, ...getIdentityKey() }, null, 2) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: JSON.stringify({ success: false, error: error instanceof Error ? error.message : 'Identity failed' }, null, 2) }] };
    }
  }
);

server.registerTool(
  'ordnet_sign_message',
  {
    title: 'Sign Message (BRC-100)',
    description: `Sign an arbitrary message with the wallet's private key (BRC-100 createSignature).

Use this to prove control of the identity key, authenticate to a service, or
sign an x402 payment authorization off-chain. The private key never leaves the
server. Requires an initialized wallet.

Args:
  - message (string): the message to sign

Returns:
  { publicKey, signature, messageHash }`,
    inputSchema: SignMessageSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  async ({ message }) => {
    try {
      requireWallet();
      return { content: [{ type: 'text', text: JSON.stringify({ success: true, ...signMessage(message) }, null, 2) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: JSON.stringify({ success: false, error: error instanceof Error ? error.message : 'Sign failed' }, null, 2) }] };
    }
  }
);

server.registerTool(
  'ordnet_verify_message',
  {
    title: 'Verify Message Signature (BRC-100)',
    description: `Verify a signature against a message and public key (BRC-100 verifySignature).

Does NOT require a wallet — anyone can verify. Use this to check that a
counterparty's message (e.g. a payment authorization or a signed quote) really
came from the holder of a given public key.

Args:
  - message (string): the original message
  - signature (string): signature hex from ordnet_sign_message
  - publicKey (string): compressed public key hex of the claimed signer

Returns:
  { valid: boolean }`,
    inputSchema: VerifyMessageSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  async ({ message, signature, publicKey }) => {
    const valid = verifyMessage(message, signature, publicKey);
    return { content: [{ type: 'text', text: JSON.stringify({ success: true, valid }, null, 2) }] };
  }
);

server.registerTool(
  'ordnet_derive_payment_address',
  {
    title: 'Derive Payment Address (BRC-42/29)',
    description: `Derive a unique, deterministic payment address for a given invoice or
reference string (BRC-42/29-style key derivation).

Each invoice number yields a different address controlled by the same wallet,
so incoming payments for different invoices are unlinkable on-chain — the
foundation for clean x402 payment flows. The same invoice always derives the
same address, so a payer and payee can compute it independently. Requires an
initialized wallet.

Args:
  - invoiceNumber (string): invoice/reference string

Returns:
  { address, publicKey, invoiceNumber }`,
    inputSchema: DeriveChildSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  async ({ invoiceNumber }) => {
    try {
      requireWallet();
      return { content: [{ type: 'text', text: JSON.stringify({ success: true, ...deriveChildAddress(invoiceNumber) }, null, 2) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: JSON.stringify({ success: false, error: error instanceof Error ? error.message : 'Derivation failed' }, null, 2) }] };
    }
  }
);


// ============================================================================
// v3.1: x402 client — the buyer side (pillar 1 complete)
// ============================================================================

server.registerTool(
  'ordnet_x402_quote',
  {
    title: 'x402 Price Quote (no payment)',
    description: `Inspect an x402-paywalled URL WITHOUT paying: returns the price,
payTo address, and payment requirements from the HTTP 402 response.

Use this to check costs before committing. Free and read-only.

Args:
  - url (string): resource URL
  - method (string, optional): GET or POST (default GET)

Returns:
  { isPaywalled, priceSats?, network?, payTo?, description?, accepts }`,
    inputSchema: X402QuoteSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async ({ url, method }) => {
    try {
      const q = await x402Quote(url, method ?? 'GET');
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            isPaywalled: q.isPaywalled,
            status: q.status,
            priceSats: q.bsvOffer ? parseInt(q.bsvOffer.maxAmountRequired, 10) : null,
            network: q.bsvOffer?.network ?? null,
            payTo: q.bsvOffer?.payTo ?? null,
            description: q.bsvOffer?.description ?? null,
            bsvSupported: q.bsvOffer !== null,
            accepts: q.accepts
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ success: false, error: error instanceof Error ? error.message : 'Quote failed' }, null, 2)
        }]
      };
    }
  }
);

server.registerTool(
  'ordnet_x402_fetch',
  {
    title: 'Fetch x402 Resource (auto-pay)',
    description: `Consume an x402-paywalled resource in one call: detect the 402,
pay the quoted amount in native BSV sats from the loaded wallet, retry with
proof, and return the resource plus the settlement receipt.

Safety:
  - maxSats is REQUIRED: the tool refuses quotes above it (agent-set budget)
  - the spend policy (ordnet_policy_status) is enforced on the payment
  - only the 'exact' scheme on network 'bsv' is supported; other networks
    (e.g. USDC on Base) are reported honestly as unsupported
  - non-paywalled URLs are fetched and returned without any payment

Args:
  - url (string): resource URL
  - method (string, optional): GET or POST (default GET)
  - maxSats (number): spending guard in satoshis

Returns:
  { status, body, paid?: { txid, satoshis, payTo }, receipt? }`,
    inputSchema: X402FetchSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async ({ url, method, maxSats }) => {
    try {
      const m = method ?? 'GET';
      const q = await x402Quote(url, m);

      if (!q.isPaywalled) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ success: true, status: q.status, paid: null, body: q.body }, null, 2)
          }]
        };
      }
      if (!q.bsvOffer) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: false,
              error: 'Resource is paywalled but offers no exact/bsv payment option; cannot pay from a BSV wallet.',
              accepts: q.accepts
            }, null, 2)
          }]
        };
      }

      const priceSats = parseInt(q.bsvOffer.maxAmountRequired, 10);
      if (!Number.isFinite(priceSats) || priceSats < 1) {
        throw new Error(`Invalid quoted price: ${q.bsvOffer.maxAmountRequired}`);
      }
      if (priceSats > maxSats) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: false,
              error: `Quoted price ${priceSats} sats exceeds your maxSats guard (${maxSats}). Not paying.`,
              priceSats, maxSats
            }, null, 2)
          }]
        };
      }

      // Pay through the exact same machinery as ordnet_send (wallet + policy)
      const wallet = requireWallet();
      // K8/H8 — the opReturnHint comes from the (untrusted) counterparty's 402
      // response and drives the transaction size, hence the miner fee. A huge
      // hint is a way to inflate the fee past what the policy would have caught
      // if it only looked at the price. Cap it hard here; the miner fee is now
      // counted by the guard, but there is no reason to build a bloated tx.
      const opReturnHint = q.bsvOffer.extra?.opReturnHint;
      if (typeof opReturnHint === 'string' && Buffer.byteLength(opReturnHint, 'utf8') > 1024) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              success: false,
              error: `Refused: the counterparty's opReturnHint is ${Buffer.byteLength(opReturnHint, 'utf8')} bytes (max 1024). An oversized hint inflates the miner fee.`,
            }, null, 2)
          }]
        };
      }
      const utxos = await fetchUTXOs(wallet.address);
      const payment = createPaymentTx(
        utxos,
        [{ address: q.bsvOffer.payTo, satoshis: priceSats }],
        opReturnHint
      );
      const { txid } = await broadcastGuarded(
        broadcastTransaction, payment.rawHex, wallet.address, payment.minerFee
      );

      const result = await x402RetryWithProof(url, m, txid, q.bsvOffer.extra?.invoiceId);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: result.status >= 200 && result.status < 300,
            status: result.status,
            paid: { txid, satoshis: priceSats, payTo: q.bsvOffer.payTo },
            receipt: result.receipt,
            body: result.body
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ success: false, error: error instanceof Error ? error.message : 'x402 fetch failed' }, null, 2)
        }]
      };
    }
  }
);

// ============================================================================
// Resources
// ============================================================================

server.registerResource(
  'service-fees',
  'ordnet://fees',
  {
    description: 'Current ORDnet service fee structure',
    mimeType: 'application/json'
  },
  async () => ({
    contents: [{
      uri: 'ordnet://fees',
      mimeType: 'application/json',
      text: JSON.stringify({
        total: TOTAL_SERVICE_FEES,
        outputs: SERVICE_FEE_OUTPUTS,
        minerFeeRate: '0.15 sat/byte (150 sats/KB), minimum 200 sats',
        note: 'All fees are in satoshis; structure identical to ordmail-v10-standalone-026.html'
      }, null, 2)
    }]
  })
);

server.registerResource(
  'domain-extensions',
  'ordnet://extensions',
  {
    description: 'Supported domain extensions by chain',
    mimeType: 'application/json'
  },
  async () => ({
    contents: [{
      uri: 'ordnet://extensions',
      mimeType: 'application/json',
      text: JSON.stringify({
        universal: ['.sats'],
        btc: ['.btc', '.ord', '.xbt', '.gm', '.unisat', '.x'],
        bsv: ['.bsv'],
        doge: ['.doge', '.shibe'],
        ltc: ['.ltc'],
        bch: ['.bch'],
        bells: ['.bells'],
        lky: ['.lky'],
        pep: ['.pep'],
        jkc: ['.jkc'],
        nmc: ['.nmc', '.bit'],
        rvn: ['.rvn'],
        cs: ['.cs']
      }, null, 2)
    }]
  })
);

// ============================================================================
// Transport Setup
// ============================================================================

async function runStdio(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('ORDnet MCP Server v3.1 running on stdio');
}

async function runHTTP(): Promise<void> {
  // ==========================================================================
  // v2.4 SECURITY: HTTP transport is fail-closed.
  // The server REFUSES to start without ORDNET_MCP_AUTH_TOKEN. Every /mcp
  // request must carry "Authorization: Bearer <token>". Without this, the
  // remote endpoint (mcp.ordnet.io) would expose all wallet tools to the
  // entire internet.
  // ==========================================================================
  const authToken = process.env.ORDNET_MCP_AUTH_TOKEN;
  if (!authToken || authToken.length < 32) {
    console.error(
      'FATAL: TRANSPORT=http requires ORDNET_MCP_AUTH_TOKEN (min. 32 chars).\n' +
      'Generate one with: openssl rand -hex 32\n' +
      'Refusing to start an unauthenticated public MCP endpoint.'
    );
    process.exit(1);
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '2mb' }));

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '3.1.0' });
  });

  // Bearer auth on everything except /health
  app.use((req, res, next) => {
    if (req.path === '/health') return next();
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (token.length !== authToken.length ||
        !timingSafeEqual(Buffer.from(token), Buffer.from(authToken))) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  });

  app.post('/mcp', async (req, res) => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });
    res.on('close', () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  
  const port = parseInt(process.env.PORT || '3000');
  app.listen(port, () => {
    console.error(`ORDnet MCP Server v3.1 running on http://localhost:${port}/mcp (bearer auth enforced)`);
  });
}

// ============================================================================
// Main
// ============================================================================

const transport = process.env.TRANSPORT || 'stdio';

if (transport === 'http') {
  runHTTP().catch(error => {
    console.error('Server error:', error);
    process.exit(1);
  });
} else {
  runStdio().catch(error => {
    console.error('Server error:', error);
    process.exit(1);
  });
}
