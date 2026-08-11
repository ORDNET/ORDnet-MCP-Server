/**
 * ORDnet MCP Server - Type Definitions
 */

import type { ContentType } from './constants.js';
export type { ContentType } from './constants.js';

// ============================================================================
// Wallet Types
// ============================================================================

export interface WalletInfo {
  address: string;
  publicKey: string;
  balanceSatoshis: number;
  balanceBSV: string;
  utxoCount: number;
}

export interface UTXO {
  txid: string;
  vout: number;
  satoshis: number;
  script: string;
  scriptPubKey: string;
}

export interface WalletBalance {
  confirmed: number;
  unconfirmed: number;
  total: number;
}

// ============================================================================
// Transaction Types
// ============================================================================

export interface InscriptionRequest {
  content: string;
  contentType: ContentType;
  feePerByte?: number;
}

export interface TransactionResult {
  txid: string;
  inscriptionId: string;
  rawHex: string;
  fee: number;
  size: number;
  outputs: TransactionOutput[];
}

export interface TransactionOutput {
  index: number;
  satoshis: number;
  address?: string;
  description: string;
}

export interface FeeEstimate {
  contentSize: number;
  estimatedTxSize: number;
  feePerByte: number;
  minerFee: number;
  serviceFee: number;
  totalCost: number;
  breakdown: {
    ordinalOutput: number;
    opReturnOutput: number;
    minerFee: number;
  } & Record<string, number>;
}

// ============================================================================
// Domain/SNS Types
// ============================================================================

export interface DomainInfo {
  name: string;
  extension: string;
  fullName: string;
  owner?: string;
  inscriptionId?: string;
  genesisHeight?: number;
  genesisTimestamp?: string;
  protocol: 'sns' | 'opns';
}

export interface DomainRegistration {
  p: 'sns' | 'opns';
  op: 'reg';
  name: string;
}

export interface DomainTransfer {
  p: 'sns' | 'opns';
  op: 'transfer';
  name: string;
  to: string;
}

// ============================================================================
// Bitmap/Map Types
// ============================================================================

export interface BitmapInfo {
  blockNumber: number;
  extension: string;
  fullName: string;
  owner?: string;
  inscriptionId?: string;
  chain: string;
}

// ============================================================================
// Search/Registry Types
// ============================================================================

export interface SearchResult {
  inscriptionId: string;
  contentType: string;
  contentSize: number;
  owner: string;
  genesisHeight: number;
  genesisTimestamp: string;
  txid: string;
}

export interface RegistryEntry {
  name: string;
  protocol: string;
  chain: string;
  owner: string;
  inscriptionId: string;
  genesisBlock: number;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// API Response Types
// ============================================================================

export interface WOCBalanceResponse {
  confirmed: number;
  unconfirmed: number;
}

export interface WOCUnspentResponse {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
}

export interface WOCBroadcastResponse {
  txid?: string;
  error?: string;
}

// ============================================================================
// MCP Tool Response Types
// ============================================================================

export interface ToolSuccess<T> {
  success: true;
  data: T;
}

export interface ToolError {
  success: false;
  error: string;
  code?: string;
  suggestion?: string;
}

export type ToolResult<T> = ToolSuccess<T> | ToolError;

// ============================================================================
// Wallet Security Types (V2.1)
// ============================================================================

export enum WalletSecurityTier {
  ENVIRONMENT = 'environment',      // Highest: from env var
  ENCRYPTED = 'encrypted',          // Middle: AES-256-GCM encrypted
  PLAINTEXT = 'plaintext'           // Lowest: plaintext WIF (not recommended)
}

export interface WalletConfig {
  tier: WalletSecurityTier;
  wif?: string;                     // Only for plaintext tier
  encryptedData?: string;           // Only for encrypted tier
  envVarName?: string;              // Only for environment tier
}

export interface EncryptedWallet {
  iv: string;                       // Base64 encoded IV
  data: string;                     // Base64 encoded encrypted data
  tag: string;                      // Base64 encoded auth tag
  salt: string;                     // Base64 encoded salt
}
